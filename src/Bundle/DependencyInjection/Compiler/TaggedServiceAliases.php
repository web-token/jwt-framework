<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use InvalidArgumentException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use function is_array;
use function is_string;
use function sprintf;
use function trigger_deprecation;

/**
 * Adds the services carrying a tag to a factory, each one under the alias given by the tag.
 *
 * @internal
 */
trait TaggedServiceAliases
{
    /**
     * The factory keeps one service per alias: when two services share an alias, the one tagged last replaces the
     * other.
     */
    private function addTaggedServices(ContainerBuilder $container, Definition $factory, string $tag, string $label): void
    {
        $owners = [];
        foreach ($container->findTaggedServiceIds($tag) as $id => $tags) {
            foreach ($tags as $attributes) {
                $alias = is_array($attributes) ? $attributes['alias'] ?? null : null;
                if ($alias === null) {
                    throw new InvalidArgumentException(sprintf(
                        'The %s "%s" does not have any "alias" attribute.',
                        $label,
                        $id
                    ));
                }
                if (is_string($alias)) {
                    $owner = $owners[$alias] ?? $id;
                    if ($owner !== $id) {
                        trigger_deprecation(
                            'web-token/jwt-framework',
                            '4.3.0',
                            'The services "%s" and "%s" are both tagged "%s" with the alias "%s": "%s" replaces "%s". Sharing an alias between two services is deprecated and will not be possible in 5.0.0; give each service an alias of its own.',
                            $owner,
                            $id,
                            $tag,
                            $alias,
                            $id,
                            $owner
                        );
                    }
                    $owners[$alias] = $id;
                }
                $factory->addMethodCall('add', [$alias, new Reference($id)]);
            }
        }
    }
}

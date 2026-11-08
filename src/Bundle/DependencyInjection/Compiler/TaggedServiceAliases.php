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

/**
 * Adds the services carrying a tag to a factory, each one under the alias given by the tag.
 *
 * @internal
 */
trait TaggedServiceAliases
{
    /**
     * An alias names a single service, which may carry several aliases.
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
                        throw new InvalidArgumentException(sprintf(
                            'The services "%s" and "%s" are both tagged "%s" with the alias "%s", but an alias names a single service. Give each service an alias of its own.',
                            $owner,
                            $id,
                            $tag,
                            $alias
                        ));
                    }
                    $owners[$alias] = $id;
                }
                $factory->addMethodCall('add', [$alias, new Reference($id)]);
            }
        }
    }
}

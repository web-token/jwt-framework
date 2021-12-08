<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use InvalidArgumentException;
use Jose\Bundle\JoseFramework\Routing\JWKSetLoader;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final class KeySetControllerCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(JWKSetLoader::class)) {
            return;
        }

        $definition = $container->getDefinition(JWKSetLoader::class);

        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.jwk_uri.controller');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            foreach ($tags as $attributes) {
                if (! isset($attributes['path'])) {
                    throw new InvalidArgumentException(sprintf(
                        'The controller "%s" does not have any "path" attribute.',
                        $id
                    ));
                }
                $definition->addMethodCall('add', [$attributes['path'], $id]);
            }
        }
    }
}

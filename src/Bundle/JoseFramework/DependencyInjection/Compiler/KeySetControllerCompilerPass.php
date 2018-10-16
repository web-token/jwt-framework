<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Bundle\JoseFramework\Routing\JWKSetLoader;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class KeySetControllerCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition(JWKSetLoader::class)) {
            return;
        }

        $definition = $container->getDefinition(JWKSetLoader::class);

        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.jwk_uri.controller');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            foreach ($tags as $attributes) {
                if (!\array_key_exists('path', $attributes)) {
                    throw new \InvalidArgumentException(\sprintf("The algorithm '%s' does not have any 'alias' attribute.", $id));
                }
                $definition->addMethodCall('add', [$attributes['path'], $id]);
            }
        }
    }
}

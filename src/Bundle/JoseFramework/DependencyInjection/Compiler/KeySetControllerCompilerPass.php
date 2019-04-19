<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Assert\Assertion;
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
        if (!$container->hasDefinition(JWKSetLoader::class)) {
            return;
        }

        $definition = $container->getDefinition(JWKSetLoader::class);

        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.jwk_uri.controller');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            foreach ($tags as $attributes) {
                Assertion::keyExists($attributes, 'path', sprintf("The algorithm '%s' does not have any 'alias' attribute.", $id));
                $definition->addMethodCall('add', [$attributes['path'], $id]);
            }
        }
    }
}

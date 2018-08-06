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

use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class EncryptionSerializerCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition(JWESerializerManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(JWESerializerManagerFactory::class);

        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.jwe.serializer');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            $definition->addMethodCall('add', [new Reference($id)]);
        }
    }
}

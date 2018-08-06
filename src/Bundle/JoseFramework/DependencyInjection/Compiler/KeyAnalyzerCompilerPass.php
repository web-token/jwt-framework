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

use Jose\Component\KeyManagement\KeyAnalyzer\KeyAnalyzerManager;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class KeyAnalyzerCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition(KeyAnalyzerManager::class)) {
            return;
        }

        $definition = $container->getDefinition(KeyAnalyzerManager::class);

        $taggedServices = $container->findTaggedServiceIds('jose.key_analyzer');
        foreach ($taggedServices as $id => $tags) {
            $definition->addMethodCall('add', [new Reference($id)]);
        }
    }
}

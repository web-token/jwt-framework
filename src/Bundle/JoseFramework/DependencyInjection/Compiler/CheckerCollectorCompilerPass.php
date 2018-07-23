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

use Jose\Bundle\JoseFramework\DataCollector\CheckerCollector;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class CheckerCollectorCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition(CheckerCollector::class)) {
            return;
        }

        $definition = $container->getDefinition(CheckerCollector::class);

        $services = [
            'addHeaderCheckerManager' => 'jose.header_checker_manager',
            'addClaimCheckerManager' => 'jose.claim_checker_manager',
        ];
        foreach ($services as $method => $tag) {
            $this->collectServices($method, $tag, $definition, $container);
        }
    }

    private function collectServices(string $method, string $tag, Definition $definition, ContainerBuilder $container)
    {
        $taggedCheckerServices = $container->findTaggedServiceIds($tag);
        foreach ($taggedCheckerServices as $id => $tags) {
            $definition->addMethodCall($method, [$id, new Reference($id)]);
        }
    }
}

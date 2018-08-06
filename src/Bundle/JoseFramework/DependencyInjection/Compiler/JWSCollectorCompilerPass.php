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

use Jose\Bundle\JoseFramework\DataCollector\JWSCollector;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JWSCollectorCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition(JWSCollector::class)) {
            return;
        }

        $definition = $container->getDefinition(JWSCollector::class);

        $services = [
            'addJWSBuilder' => 'jose.jws_builder',
            'addJWSVerifier' => 'jose.jws_verifier',
            'addJWSLoader' => 'jose.jws_loader',
        ];
        foreach ($services as $method => $tag) {
            $this->collectServices($method, $tag, $definition, $container);
        }
    }

    private function collectServices(string $method, string $tag, Definition $definition, ContainerBuilder $container)
    {
        $taggedJWSServices = $container->findTaggedServiceIds($tag);
        foreach ($taggedJWSServices as $id => $tags) {
            $definition->addMethodCall($method, [$id, new Reference($id)]);
        }
    }
}

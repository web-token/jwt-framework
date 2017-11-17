<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Bundle\JoseFramework\DataCollector\JoseCollector;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class DataCollectorServicesCompilerPass.
 */
final class DataCollectorServicesCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition(JoseCollector::class)) {
            return;
        }

        $definition = $container->getDefinition(JoseCollector::class);

        $services = [
            'addJWSBuilder' => 'jose.jws_builder',
            'addJWSVerifier' => 'jose.jws_verifier',
            'addJWEBuilder' => 'jose.jwe_builder',
            'addJWEDecrypter' => 'jose.jwe_decrypter',
            'addHeaderCheckerManager' => 'jose.header_checker_manager',
            'addClaimCheckerManager' => 'jose.claim_checker_manager',
            'addJWK' => 'jose.jwk',
            'addJWKSet' => 'jose.jwkset',
        ];
        foreach ($services as $method => $tag) {
            $this->collectServices($method, $tag, $definition, $container);
        }
    }

    /**
     * @param string           $method
     * @param string           $tag
     * @param Definition       $definition
     * @param ContainerBuilder $container
     */
    private function collectServices(string $method, string $tag, Definition $definition, ContainerBuilder $container)
    {
        $taggedAlgorithmServices = $container->findTaggedServiceIds($tag);
        foreach ($taggedAlgorithmServices as $id => $tags) {
            $definition->addMethodCall($method, [$id, new Reference($id)]);
        }
    }
}

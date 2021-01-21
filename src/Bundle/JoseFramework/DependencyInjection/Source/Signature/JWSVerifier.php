<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature;

use Jose\Bundle\JoseFramework\Services\JWSVerifierFactory;
use Jose\Component\Signature\JWSVerifier as JWSVerifierService;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JWSVerifier extends AbstractSignatureSource
{
    public function name(): string
    {
        return 'verifiers';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.jws_verifier.%s', $name);
            $definition = new Definition(JWSVerifierService::class);
            $definition
                ->setFactory([new Reference(JWSVerifierFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['signature_algorithms'],
                ])
                ->addTag('jose.jws_verifier')
                ->setPublic($itemConfig['is_public'])
            ;
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
        }
    }
}

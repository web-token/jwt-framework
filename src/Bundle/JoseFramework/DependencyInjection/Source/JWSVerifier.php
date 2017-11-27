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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\JWSVerifier as JWSVerifierService;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class JWSVerifier.
 */
final class JWSVerifier extends AbstractSignatureSource
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'jws_verifiers';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
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
                ->setPublic($itemConfig['is_public']);

            $container->setDefinition($service_id, $definition);
        }
    }
}

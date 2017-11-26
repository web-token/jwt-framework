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

namespace Jose\Bundle\Encryption\DependencyInjection\Source;

use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEBuilder as JWEBuilderService;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class JWEBuilder.
 */
final class JWEBuilder extends AbstractSource
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'jwe_builders';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.jwe_builder.%s', $name);
            $definition = new Definition(JWEBuilderService::class);
            $definition
                ->setFactory([new Reference(JWEBuilderFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['key_encryption_algorithms'],
                    $itemConfig['content_encryption_algorithms'],
                    $itemConfig['compression_methods'],
                ])
                ->addTag('jose.jwe_builder')
                ->setPublic($itemConfig['is_public']);

            $container->setDefinition($service_id, $definition);
        }
    }
}

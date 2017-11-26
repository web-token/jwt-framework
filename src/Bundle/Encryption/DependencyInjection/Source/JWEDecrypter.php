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

use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\JWEDecrypter as JWEDecrypterService;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class JWEDecrypter.
 */
final class JWEDecrypter extends AbstractSource
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'jwe_decrypters';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.jwe_decrypter.%s', $name);
            $definition = new Definition(JWEDecrypterService::class);
            $definition
                ->setFactory([new Reference(JWEDecrypterFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['key_encryption_algorithms'],
                    $itemConfig['content_encryption_algorithms'],
                    $itemConfig['compression_methods'],
                ])
                ->addTag('jose.jwe_decrypter')
                ->setPublic($itemConfig['is_public']);

            $container->setDefinition($service_id, $definition);
        }
    }
}

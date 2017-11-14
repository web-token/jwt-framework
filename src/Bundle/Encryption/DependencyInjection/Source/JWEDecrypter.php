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

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\JWEDecrypter as JWEDecrypterService;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class JWEDecrypter.
 */
final class JWEDecrypter implements Source
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
                    $itemConfig['header_checkers'],
                ])
                ->addTag('jose.jwe_decrypter')
                ->setPublic($itemConfig['is_public']);

            $container->setDefinition($service_id, $definition);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode($this->name())
                    ->useAttributeAsKey('name')
                    ->prototype('array')
                        ->children()
                            ->booleanNode('is_public')
                                ->info('If true, the service will be public, else private.')
                                ->defaultTrue()
                            ->end()
                            ->arrayNode('key_encryption_algorithms')
                                ->info('A list of supported key encryption algorithms.')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('content_encryption_algorithms')
                                ->info('A list of supported content encryption algorithms.')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('compression_methods')
                                ->info('A list of supported compression methods.')
                                ->useAttributeAsKey('name')
                                ->defaultValue(['DEF'])
                                ->prototype('scalar')->end()
                            ->end()
                            ->arrayNode('header_checkers')
                                ->info('A list of headers to check.')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->prototype('scalar')->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config): ?array
    {
        return null;
    }
}

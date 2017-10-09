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

use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceInterface;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEBuilder as JWEBuilderService;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class JWEBuilder.
 */
final class JWEBuilder implements SourceInterface
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
    public function createService(array $config, ContainerBuilder $container)
    {
        foreach ($config as $name => $itemConfig) {
            $service_id = sprintf('jose.jwe_builder.%s', $name);
            $definition = new Definition(JWEBuilderService::class);
            $definition
                ->setFactory([new Reference(JWEBuilderFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['key_encryption_algorithms'],
                    $itemConfig['content_encryption_algorithms'],
                    $itemConfig['compression_methods'],
                ])
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

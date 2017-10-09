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

namespace Jose\Bundle\KeyManagement\DependencyInjection\Source;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Class JKUSource.
 */
final class JKUSource implements SourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'jku_factory';
    }

    /**
     * {@inheritdoc}
     */
    public function createService(array $config, ContainerBuilder $container)
    {
        $container->setAlias('jose.http_client', $config['client']);
        $container->setAlias('jose.request_factory', $config['request_factory']);
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode('jku_factory')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('client')
                            ->info('HTTP Client used to retrieve key sets.')
                            ->isRequired()
                            ->defaultNull()
                        ->end()
                        ->scalarNode('request_factory')
                            ->defaultValue('Http\Message\MessageFactory\GuzzleMessageFactory')
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

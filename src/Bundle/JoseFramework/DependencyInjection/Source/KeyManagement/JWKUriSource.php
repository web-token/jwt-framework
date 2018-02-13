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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use Jose\Bundle\JoseFramework\Controller\JWKSetController;
use Jose\Bundle\JoseFramework\Controller\JWKSetControllerFactory;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class JKUriSource.
 */
final class JWKUriSource implements Source
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'jwk_uris';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.controller.%s', $name);
            $definition = new Definition(JWKSetController::class);
            $definition->setFactory([new Reference(JWKSetControllerFactory::class), 'create']);
            $definition->setArguments([new Reference($itemConfig['id']), $itemConfig['max_age']]);
            $definition->addTag('jose.jwk_uri.controller', ['path' => $itemConfig['path']]);
            $definition->addTag('controller.service_arguments');
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
                ->arrayNode('jwk_uris')
                    ->treatFalseLike([])
                    ->treatNullLike([])
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode('id')
                                ->info('The service ID of the Key Set to share.')
                                ->isRequired()
                            ->end()
                            ->scalarNode('path')
                                ->info('To share the JWKSet, then set a valid path (e.g. "/jwkset.json").')
                                ->isRequired()
                            ->end()
                            ->integerNode('max_age')
                                ->info('When share, this value indicates how many seconds the HTTP client should keep the key in cache. Default is 21600 = 6 hours.')
                                ->defaultValue(21600)
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

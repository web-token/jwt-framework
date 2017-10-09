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

namespace Jose\Bundle\KeyManagement\DependencyInjection\Source\JWKSetSource;

use Jose\Bundle\KeyManagement\Controller\JWKSetController;
use Jose\Bundle\KeyManagement\Controller\JWKSetControllerFactory;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\AbstractSource;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class AbstractJWKSetSource.
 */
abstract class AbstractJWKSetSource extends AbstractSource implements JWKSetSourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function create(ContainerBuilder $container, string $type, string $name, array $config)
    {
        parent::create($container, $type, $name, $config);

        if (null !== $config['path']) {
            $jwkset_id = sprintf('jose.key_set.%s', $name);
            $controller_definition = new Definition(JWKSetController::class);
            $controller_definition->setFactory([new Reference(JWKSetControllerFactory::class), 'create']);
            $controller_definition->setArguments([new Reference($jwkset_id), $config['max_age']]);
            $controller_definition->addTag('jose.key_set.controller', ['path' => $config['path']]);
            $controller_id = sprintf('jose.controller.%s', $name);
            $container->setDefinition($controller_id, $controller_definition);
        }
    }

    /**
     * @param NodeDefinition $node
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
                ->scalarNode('path')
                    ->info('To share the JWKSet, then set a valid path (e.g. "/jwkset.json").')
                    ->defaultNull()
                ->end()
                ->integerNode('max_age')
                    ->info('When share, this value indicates how many seconds the HTTP client should keep the key in cache. Default is 21600 = 6 hours.')
                    ->defaultValue(21600)
                ->end()
            ->end();
    }
}

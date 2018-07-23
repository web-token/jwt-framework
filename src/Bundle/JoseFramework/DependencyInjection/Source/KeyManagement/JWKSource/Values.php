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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\AbstractSource;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class Values extends AbstractSource implements JWKSource
{
    /**
     * {@inheritdoc}
     */
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(JWK::class);
        $definition->setFactory([
            new Reference(JWKFactory::class),
            'createFromValues',
        ]);
        $definition->setArguments([
            $config['values'],
        ]);
        $definition->addTag('jose.jwk');

        return $definition;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey(): string
    {
        return 'values';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
            ->arrayNode('values')
            ->info('Values of the key.')
            ->isRequired()
            ->useAttributeAsKey('key')
            ->variablePrototype()->end()
            ->end()
            ->end();
    }
}

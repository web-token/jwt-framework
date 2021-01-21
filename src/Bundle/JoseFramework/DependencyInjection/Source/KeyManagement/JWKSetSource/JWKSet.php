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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSetSource;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\AbstractSource;
use Jose\Component\Core\JWKSet as JWKSetAlias;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JWKSet extends AbstractSource implements JWKSetSource
{
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(JWKSetAlias::class);
        $definition->setFactory([
            new Reference(JWKFactory::class),
            'createFromJsonObject',
        ]);
        $definition->setArguments([
            $config['value'],
        ]);
        $definition->addTag('jose.jwkset');

        return $definition;
    }

    public function getKeySet(): string
    {
        return 'jwkset';
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        parent::addConfiguration($node);
        $node
            ->children()
            ->scalarNode('value')
            ->info('The JWKSet object.')
            ->isRequired()
            ->end()
            ->end()
        ;
    }
}

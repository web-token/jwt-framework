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

/**
 * Class JWK.
 */
final class JWK extends AbstractSource implements JWKSource
{
    /**
     * {@inheritdoc}
     */
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(\Jose\Component\Core\JWK::class);
        $definition->setFactory([
            new Reference(JWKFactory::class),
            'createFromJsonObject',
        ]);
        $definition->setArguments([
            $config['value'],
        ]);
        $definition->addTag('jose.jwk');

        return $definition;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey(): string
    {
        return 'jwk';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
        $node
            ->children()
                ->scalarNode('value')
                    ->info('The JWK object')
                    ->isRequired()
                ->end()
            ->end();
    }
}

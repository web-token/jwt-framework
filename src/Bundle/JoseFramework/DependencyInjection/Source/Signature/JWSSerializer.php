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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class JWSSerializer.
 */
final class JWSSerializer implements Source
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'serializers';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.jws_serializer.%s', $name);
            $definition = new Definition(JWSSerializerManager::class);
            $definition
                ->setFactory([new Reference(JWSSerializerManagerFactory::class), 'create'])
                ->setArguments([$itemConfig['serializers']])
                ->addTag('jose.jws_serializer_manager')
                ->setPublic($itemConfig['is_public']);

            $container->setDefinition($service_id, $definition);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $node->children()
            ->arrayNode($this->name())
                ->treatFalseLike([])
                ->treatNullLike([])
                ->useAttributeAsKey('name')
                ->arrayPrototype()
                    ->children()
                        ->booleanNode('is_public')
                            ->info('If true, the service will be public, else private.')
                            ->defaultTrue()
                        ->end()
                        ->arrayNode('serializers')
                            ->info('A list of JWS serializers aliases.')
                            ->isRequired()
                            ->scalarPrototype()->end()
                            ->treatNullLike([])
                            ->treatFalseLike([])
                            ->requiresAtLeastOneElement()
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

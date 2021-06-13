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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory;
use Jose\Component\Signature\JWSLoader as JWSLoaderService;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JWSLoader implements Source
{
    public function name(): string
    {
        return 'loaders';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.jws_loader.%s', $name);
            $definition = new Definition(JWSLoaderService::class);
            $definition
                ->setFactory([new Reference(JWSLoaderFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['serializers'],
                    $itemConfig['signature_algorithms'],
                    $itemConfig['header_checkers'],
                ])
                ->addTag('jose.jws_loader')
                ->setPublic($itemConfig['is_public'])
            ;
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }

            $container->setDefinition($service_id, $definition);
            $container->registerAliasForArgument($service_id, JWSLoaderService::class, $name.'JwsLoader');
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node
            ->children()
            ->arrayNode($this->name())
            ->requiresAtLeastOneElement()
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children()
            ->booleanNode('is_public')
            ->info('If true, the service will be public, else private.')
            ->defaultTrue()
            ->end()
            ->arrayNode('signature_algorithms')
            ->info('A list of signature algorithm aliases.')
            ->useAttributeAsKey('name')
            ->isRequired()
            ->scalarPrototype()->end()
            ->end()
            ->arrayNode('serializers')
            ->info('A list of signature serializer aliases.')
            ->useAttributeAsKey('name')
            ->requiresAtLeastOneElement()
            ->scalarPrototype()->end()
            ->end()
            ->arrayNode('header_checkers')
            ->info('A list of header checker aliases.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->scalarPrototype()->end()
            ->end()
            ->arrayNode('tags')
            ->info('A list of tags to be associated to the service.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->variablePrototype()->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
        ;
    }

    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\Services\ClaimCheckerManager;
use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class ClaimChecker implements Source
{
    public function name(): string
    {
        return 'claims';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.claim_checker.%s', $name);
            $definition = new Definition(ClaimCheckerManager::class);
            $definition
                ->setFactory([new Reference(ClaimCheckerManagerFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['claims'],
                ])
                ->addTag('jose.claim_checker_manager')
                ->setPublic($itemConfig['is_public'])
            ;
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node
            ->children()
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
            ->arrayNode('claims')
            ->info('A list of claim aliases to be set in the claim checker.')
            ->useAttributeAsKey('name')
            ->isRequired()
            ->scalarPrototype()->end()
            ->end()
            ->arrayNode('tags')
            ->info('A list of tags to be associated to the claim checker.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->variablePrototype()
            ->end()
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

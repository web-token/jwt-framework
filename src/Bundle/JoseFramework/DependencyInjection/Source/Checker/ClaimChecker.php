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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Signature\JWSVerifier as JWSVerifierService;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class ClaimChecker implements Source
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'claims';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = \sprintf('jose.claim_checker.%s', $name);
            $definition = new Definition(JWSVerifierService::class);
            $definition
                ->setFactory([new Reference(ClaimCheckerManagerFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['claims'],
                ])
                ->addTag('jose.claim_checker_manager')
                ->setPublic($itemConfig['is_public']);
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(NodeDefinition $node)
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

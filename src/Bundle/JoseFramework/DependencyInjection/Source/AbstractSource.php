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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * Class AbstractSource.
 */
abstract class AbstractSource
{
    /**
     * @param ContainerBuilder $container
     * @param array            $config
     *
     * @return Definition
     */
    abstract protected function createDefinition(ContainerBuilder $container, array $config): Definition;

    /**
     * @param ContainerBuilder $container
     * @param string           $type
     * @param string           $name
     * @param array            $config
     */
    public function create(ContainerBuilder $container, string $type, string $name, array $config)
    {
        $service_id = sprintf('jose.%s.%s', $type, $name);
        $definition = $this->createDefinition($container, $config);
        $definition->setPublic($config['is_public']);
        $container->setDefinition($service_id, $definition);
    }

    /**
     * @param NodeDefinition $node
     */
    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
                ->booleanNode('is_public')
                    ->info('If true, the service will be public, else private.')
                    ->defaultTrue()
                ->end()
            ->end();
    }
}

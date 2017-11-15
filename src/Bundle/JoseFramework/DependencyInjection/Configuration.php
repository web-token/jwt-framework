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

namespace Jose\Bundle\JoseFramework\DependencyInjection;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\Core\Converter\StandardConverter;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Class Configuration.
 */
final class Configuration implements ConfigurationInterface
{
    /**
     * @var Source[]
     */
    private $serviceSources;

    /**
     * @var string
     */
    private $alias;

    /**
     * Configuration constructor.
     *
     * @param string   $alias
     * @param Source[] $serviceSources
     */
    public function __construct(string $alias, array $serviceSources)
    {
        $this->alias = $alias;
        $this->serviceSources = $serviceSources;
    }

    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root($this->alias);

        foreach ($this->serviceSources as $serviceSource) {
            $serviceSource->getNodeDefinition($rootNode);
        }

        $rootNode
            ->children()
                ->scalarNode('json_converter')
                    ->defaultValue(StandardConverter::class)
                    ->info('Converter used to encode and decode JSON objects (JWT payloads, keys, key sets...). If set to false, a service that implements JsonConverter must be set.')
                ->end()
            ->end();

        return $treeBuilder;
    }
}

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

namespace Jose\Bundle\JoseFramework\DependencyInjection;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    /**
     * @var Source[]
     */
    private $sources;

    /**
     * @var string
     */
    private $alias;

    /**
     * @param Source[] $sources
     */
    public function __construct(string $alias, array $sources)
    {
        $this->alias = $alias;
        $this->sources = $sources;
    }

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder($this->alias);
        $rootNode = $treeBuilder->getRootNode();

        foreach ($this->sources as $source) {
            $source->getNodeDefinition($rootNode);
        }

        return $treeBuilder;
    }
}

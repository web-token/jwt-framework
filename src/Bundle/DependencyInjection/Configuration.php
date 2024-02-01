<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    /**
     * @param Source[] $sources
     */
    public function __construct(
        private readonly string $alias,
        private readonly array $sources
    ) {
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

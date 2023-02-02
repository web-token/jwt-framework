<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

abstract class AbstractSource
{
    /**
     * @param array{is_public: bool, tags: array<string, array>, string?: mixed} $config
     */
    public function create(ContainerBuilder $container, string $type, string $name, array $config): void
    {
        $service_id = sprintf('jose.%s.%s', $type, $name);
        $definition = $this->createDefinition($container, $config);
        $definition->setPublic($config['is_public']);
        foreach ($config['tags'] as $id => $attributes) {
            $definition->addTag($id, $attributes);
        }
        $container->setDefinition($service_id, $definition);
        $container->registerAliasForArgument($service_id, $definition->getClass() ?? '', $name . ' ' . $type);
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        $node
            ->children()
            ->booleanNode('is_public')
            ->info('If true, the service will be public, else private.')
            ->defaultTrue()
            ->end()
            ->arrayNode('tags')
            ->info('A list of tags to be associated to the service.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->variablePrototype()
            ->end()
            ->end()
            ->end();
    }

    /**
     * @param array<string, mixed> $config
     */
    abstract protected function createDefinition(ContainerBuilder $container, array $config): Definition;
}

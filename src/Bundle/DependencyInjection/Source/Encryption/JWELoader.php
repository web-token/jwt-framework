<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Encryption;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\Services\JWELoaderFactory;
use Jose\Component\Encryption\JWELoader as JWELoaderService;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final readonly class JWELoader implements Source
{
    #[Override]
    public function name(): string
    {
        return 'loaders';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.jwe_loader.%s', $name);
            $definition = new Definition(JWELoaderService::class);
            $definition
                ->setFactory([new Reference(JWELoaderFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['serializers'],
                    $itemConfig['encryption_algorithms'],
                    $itemConfig['header_checkers'],
                ])
                ->addTag('jose.jwe_loader')
                ->setPublic($itemConfig['is_public']);
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }

            $container->setDefinition($service_id, $definition);
            $container->registerAliasForArgument($service_id, JWELoaderService::class, $name . 'JweLoader');
        }
    }

    #[Override]
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
            ->arrayNode('encryption_algorithms')
            ->info('A list of key encryption algorithm aliases.')
            ->useAttributeAsKey('name')
            ->isRequired()
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('serializers')
            ->info('A list of signature serializer aliases.')
            ->useAttributeAsKey('name')
            ->requiresAtLeastOneElement()
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('header_checkers')
            ->info('A list of header checker aliases.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('tags')
            ->info('A list of tags to be associated to the service.')
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

    #[Override]
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

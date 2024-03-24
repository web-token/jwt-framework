<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\NestedToken;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\Services\NestedTokenLoaderFactory;
use Jose\Component\NestedToken\NestedTokenLoader as NestedTokenLoaderService;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final readonly class NestedTokenLoader implements Source
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
            $service_id = sprintf('jose.nested_token_loader.%s', $name);
            $definition = new Definition(NestedTokenLoaderService::class);
            $definition
                ->setFactory([new Reference(NestedTokenLoaderFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['jwe_serializers'],
                    $itemConfig['encryption_algorithms'],
                    $itemConfig['jwe_header_checkers'],
                    $itemConfig['jws_serializers'],
                    $itemConfig['signature_algorithms'],
                    $itemConfig['jws_header_checkers'],
                ])
                ->addTag('jose.nested_token_loader')
                ->setPublic($itemConfig['is_public']);
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
            $container->registerAliasForArgument($service_id, self::class, $name . 'NestedTokenLoader');
        }
    }

    #[Override]
    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node->children()
            ->arrayNode($this->name())
            ->treatNullLike([])
            ->treatFalseLike([])
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
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('encryption_algorithms')
            ->info('A list of encryption algorithm aliases.')
            ->useAttributeAsKey('name')
            ->isRequired()
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('jws_serializers')
            ->info('A list of JWS serializer aliases.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->isRequired()
            ->requiresAtLeastOneElement()
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('jwe_serializers')
            ->info('A list of JWE serializer aliases.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->isRequired()
            ->requiresAtLeastOneElement()
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('jws_header_checkers')
            ->info('A list of header checker aliases.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('jwe_header_checkers')
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
            ->end();
    }

    #[Override]
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

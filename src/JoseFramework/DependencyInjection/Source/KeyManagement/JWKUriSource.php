<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use Jose\Bundle\JoseFramework\Controller\JWKSetController;
use Jose\Bundle\JoseFramework\Controller\JWKSetControllerFactory;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JWKUriSource implements Source
{
    public function name(): string
    {
        return 'jwk_uris';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.controller.%s', $name);
            $definition = new Definition(JWKSetController::class);
            $definition->setFactory([new Reference(JWKSetControllerFactory::class), 'create']);
            $definition->setArguments([new Reference($itemConfig['id'])]);
            $definition->addTag('jose.jwk_uri.controller', [
                'path' => $itemConfig['path'],
            ]);
            $definition->addTag('controller.service_arguments');
            $definition->setPublic($itemConfig['is_public']);
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
            $container->registerAliasForArgument($service_id, JWKSetController::class, $name . 'JwkSetController');
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node->children()
            ->arrayNode('jwk_uris')
            ->treatFalseLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children()
            ->scalarNode('id')
            ->info('The service ID of the Key Set to share.')
            ->isRequired()
            ->end()
            ->scalarNode('path')
            ->info('To share the JWKSet, then set a valid path (e.g. "/jwkset.json").')
            ->isRequired()
            ->end()
            ->arrayNode('tags')
            ->info('A list of tags to be associated to the service.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->variablePrototype()
            ->end()
            ->end()
            ->booleanNode('is_public')
            ->info('If true, the service will be public, else private.')
            ->defaultTrue()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

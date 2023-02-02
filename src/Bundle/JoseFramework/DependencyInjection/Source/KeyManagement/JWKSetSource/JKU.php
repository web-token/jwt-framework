<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSetSource;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\AbstractSource;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JKU extends AbstractSource implements JWKSetSource
{
    /**
     * @param array<string, mixed> $config
     */
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(JWKSet::class);
        $definition->setFactory([new Reference(JKUFactory::class), 'loadFromUrl']);
        $definition->setArguments([$config['url'], $config['headers']]);
        $definition->addTag('jose.jwkset');

        return $definition;
    }

    public function getKeySet(): string
    {
        return 'jku';
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        parent::addConfiguration($node);
        $node
            ->children()
            ->scalarNode('url')
            ->info('URL of the key set.')
            ->isRequired()
            ->end()
            ->arrayNode('headers')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->info('Header key/value pairs added to the request.')
            ->useAttributeAsKey('name')
            ->variablePrototype()
            ->end()
            ->end()
            ->end();
    }
}

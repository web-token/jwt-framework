<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\AbstractSource;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JWKSet extends AbstractSource implements JWKSource
{
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(JWK::class);
        $definition->setFactory([new Reference(JWKFactory::class), 'createFromKeySet']);
        $definition->setArguments([new Reference($config['key_set']), $config['index']]);
        $definition->addTag('jose.jwk');

        return $definition;
    }

    public function getKey(): string
    {
        return 'jwkset';
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        parent::addConfiguration($node);
        $node
            ->children()
            ->scalarNode('key_set')
            ->info('The key set service.')
            ->isRequired()
            ->end()
            ->integerNode('index')
            ->info('The index of the key in the key set.')
            ->isRequired()
            ->end()
            ->end()
        ;
    }
}

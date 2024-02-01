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

class KeyFile extends AbstractSource implements JWKSource
{
    /**
     * @param array<string, mixed> $config
     */
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(JWK::class);
        $definition->setFactory([new Reference(JWKFactory::class), 'createFromKeyFile']);
        $definition->setArguments([$config['path'], $config['password'], $config['additional_values']]);
        $definition->addTag('jose.jwk');

        return $definition;
    }

    public function getKey(): string
    {
        return 'file';
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        parent::addConfiguration($node);
        $node
            ->children()
            ->scalarNode('path')
            ->info('Path of the key file.')
            ->isRequired()
            ->end()
            ->scalarNode('password')
            ->info('Password used to decrypt the key (optional).')
            ->defaultNull()
            ->end()
            ->arrayNode('additional_values')
            ->info('Additional values to be added to the key.')
            ->defaultValue([])
            ->useAttributeAsKey('key')
            ->variablePrototype()
            ->end()
            ->end()
            ->end();
    }
}

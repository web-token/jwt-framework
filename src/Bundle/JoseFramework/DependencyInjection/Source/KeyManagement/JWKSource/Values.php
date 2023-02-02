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

class Values extends AbstractSource implements JWKSource
{
    /**
     * @param array<string, mixed> $config
     */
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(JWK::class);
        $definition->setFactory([new Reference(JWKFactory::class), 'createFromValues']);
        $definition->setArguments([$config['values']]);
        $definition->addTag('jose.jwk');

        return $definition;
    }

    public function getKey(): string
    {
        return 'values';
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        parent::addConfiguration($node);
        $node
            ->children()
            ->arrayNode('values')
            ->info('Values of the key.')
            ->isRequired()
            ->useAttributeAsKey('key')
            ->variablePrototype()
            ->end()
            ->end()
            ->end();
    }
}

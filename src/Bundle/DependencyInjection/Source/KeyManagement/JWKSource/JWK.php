<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\AbstractSource;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JWK extends AbstractSource implements JWKSource
{
    /**
     * @param array<string, mixed> $config
     */
    public function createDefinition(ContainerBuilder $container, array $config): Definition
    {
        $definition = new Definition(\Jose\Component\Core\JWK::class);
        $definition->setFactory([new Reference(JWKFactory::class), 'createFromJsonObject']);
        $definition->setArguments([$config['value']]);
        $definition->addTag('jose.jwk');

        return $definition;
    }

    public function getKey(): string
    {
        return 'jwk';
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        parent::addConfiguration($node);
        $node
            ->children()
            ->scalarNode('value')
            ->info('The JWK object')
            ->isRequired()
            ->end()
            ->end();
    }
}

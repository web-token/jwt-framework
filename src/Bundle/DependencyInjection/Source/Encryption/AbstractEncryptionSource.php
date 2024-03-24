<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Encryption;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;

abstract class AbstractEncryptionSource implements Source
{
    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node
            ->children()
            ->arrayNode($this->name())
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->beforeNormalization()
            ->ifTrue(
                static fn (array $v) => isset($v['key_encryption_algorithms']) || isset($v['content_encryption_algorithms'])
            )
            ->then(static function (array $v) {
                $v['encryption_algorithms'] = array_merge(
                    $v['encryption_algorithms'] ?? [],
                    $v['key_encryption_algorithms'] ?? []
                );
                $v['encryption_algorithms'] = array_merge(
                    $v['encryption_algorithms'],
                    $v['content_encryption_algorithms'] ?? []
                );
                unset($v['key_encryption_algorithms'], $v['content_encryption_algorithms']);
                $v['encryption_algorithms'] = array_values(array_unique($v['encryption_algorithms']));

                return $v;
            })
            ->end()
            ->children()
            ->booleanNode('is_public')
            ->info('If true, the service will be public, else private.')
            ->defaultTrue()
            ->end()
            ->arrayNode('encryption_algorithms')
            ->info('A list of key or content encryption algorithm aliases.')
            ->useAttributeAsKey('name')
            ->isRequired()
            ->requiresAtLeastOneElement()
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('key_encryption_algorithms')
            ->info('A list of supported key encryption algorithms.')
            ->setDeprecated(
                'web-token/jwt-bundle',
                '3.3.0',
                'The child node "%node%" at path "%path%" is deprecated and will be removed in 4.0.0. Please use "encryption_algorithms" instead.'
            )
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->defaultValue([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('content_encryption_algorithms')
            ->info('A list of supported content encryption algorithms.')
            ->useAttributeAsKey('name')
            ->setDeprecated(
                'web-token/jwt-bundle',
                '3.3.0',
                'The child node "%node%" at path "%path%" is deprecated and will be removed in 4.0.0. Please use "encryption_algorithms" instead.'
            )
            ->treatNullLike([])
            ->treatFalseLike([])
            ->defaultValue([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('compression_methods')
            ->info('A list of supported compression methods.')
            ->setDeprecated(
                'web-token/jwt-bundle',
                '3.3.0',
                'The child node "%node%" at path "%path%" is deprecated and will be removed in 4.0.0.'
            )
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->defaultValue([])
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

    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

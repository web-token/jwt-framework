<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Encryption;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\NestedTokenLoaderFactory;
use Jose\Component\Signature\JWSVerifierFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class NestedTokenLoader implements Source
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'nested_token_loaders';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        if (!$this->isEnabled()) {
            return;
        }
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('nested_token_loaders.yml');

        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.nested_token_loader.%s', $name);
            $definition = new Definition(NestedTokenLoader::class);
            $definition
                ->setFactory([new Reference(NestedTokenLoaderFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['jwe_serializers'],
                    $itemConfig['key_encryption_algorithms'],
                    $itemConfig['content_encryption_algorithms'],
                    $itemConfig['compression_methods'],
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
        }
    }

    public function getNodeDefinition(NodeDefinition $node)
    {
        if (!$this->isEnabled()) {
            return;
        }
        $node
            ->children()
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
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('key_encryption_algorithms')
                                ->info('A list of key encryption algorithm aliases.')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('content_encryption_algorithms')
                                ->info('A list of key encryption algorithm aliases.')
                                ->useAttributeAsKey('name')
                                ->isRequired()
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('compression_methods')
                                ->info('A list of compression method aliases.')
                                ->useAttributeAsKey('name')
                                ->defaultValue(['DEF'])
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('jws_serializers')
                                ->info('A list of JWS serializer aliases.')
                                ->useAttributeAsKey('name')
                                ->treatNullLike([])
                                ->treatFalseLike([])
                                ->requiresAtLeastOneElement()
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('jwe_serializers')
                                ->info('A list of JWE serializer aliases.')
                                ->useAttributeAsKey('name')
                                ->treatNullLike([])
                                ->treatFalseLike([])
                                ->requiresAtLeastOneElement()
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('jws_header_checkers')
                                ->info('A list of header checker aliases.')
                                ->useAttributeAsKey('name')
                                ->treatNullLike([])
                                ->treatFalseLike([])
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('jwe_header_checkers')
                                ->info('A list of header checker aliases.')
                                ->useAttributeAsKey('name')
                                ->treatNullLike([])
                                ->treatFalseLike([])
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('tags')
                                ->info('A list of tags to be associated to the service.')
                                ->useAttributeAsKey('name')
                                ->treatNullLike([])
                                ->treatFalseLike([])
                                ->variablePrototype()->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }

    /**
     * @return bool
     */
    private function isEnabled(): bool
    {
        return class_exists(JWEDecrypterFactory::class)
            && class_exists(JWSVerifierFactory::class)
            && class_exists(HeaderCheckerManagerFactory::class);
    }
}

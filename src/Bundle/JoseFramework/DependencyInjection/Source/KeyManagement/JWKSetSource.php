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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSetSource\JWKSetSource as JWKSetSourceInterface;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class JWKSetSource implements Source
{
    /**
     * @var null|JWKSetSourceInterface[]
     */
    private $jwkset_sources = null;

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'key_sets';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $sources = $this->getJWKSetSources();
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            foreach ($itemConfig as $sourceName => $sourceConfig) {
                if (\array_key_exists($sourceName, $sources)) {
                    $source = $sources[$sourceName];
                    $source->create($container, 'key_set', $name, $sourceConfig);
                } else {
                    throw new \LogicException(\sprintf('The JWKSet definition "%s" is not configured.', $name));
                }
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(NodeDefinition $node)
    {
        $sourceNodeBuilder = $node
            ->children()
            ->arrayNode('key_sets')
            ->treatFalseLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->validate()
            ->ifTrue(function ($config) {
                return 1 !== \count($config);
            })
            ->thenInvalid('One key set type must be set.')
            ->end()
            ->children();
        foreach ($this->getJWKSetSources() as $name => $source) {
            $sourceNode = $sourceNodeBuilder->arrayNode($name)->canBeUnset();
            $source->addConfiguration($sourceNode);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }

    /**
     * @throws \Exception
     *
     * @return JWKSetSourceInterface[]
     */
    private function getJWKSetSources(): array
    {
        if (null !== $this->jwkset_sources) {
            return $this->jwkset_sources;
        }

        // load bundled adapter factories
        $tempContainer = new ContainerBuilder();
        $tempContainer->registerForAutoconfiguration(JWKSetSourceInterface::class)->addTag('jose.jwkset_source');
        $loader = new YamlFileLoader($tempContainer, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('jwkset_sources.yml');

        $services = $tempContainer->findTaggedServiceIds('jose.jwkset_source');
        $jwkset_sources = [];
        foreach (\array_keys($services) as $id) {
            $factory = $tempContainer->get($id);
            if (!$factory instanceof JWKSetSourceInterface) {
                throw new \InvalidArgumentException();
            }
            $jwkset_sources[\str_replace('-', '_', $factory->getKeySet())] = $factory;
        }

        return $this->jwkset_sources = $jwkset_sources;
    }
}

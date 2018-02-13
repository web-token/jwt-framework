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

use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\JWKSource as JWKSourceInterface;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * Class JWKSource.
 */
final class JWKSource implements Source
{
    /**
     * @var null|JWKSourceInterface[]
     */
    private $jwkSources = null;

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'keys';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $sources = $this->getJWKSources();
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            foreach ($itemConfig as $sourceName => $sourceConfig) {
                if (array_key_exists($sourceName, $sources)) {
                    $source = $sources[$sourceName];
                    $source->create($container, 'key', $name, $sourceConfig);
                } else {
                    throw new \LogicException(sprintf('The JWK definition "%s" is not configured.', $name));
                }
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $sourceNodeBuilder = $node
            ->children()
                ->arrayNode('keys')
                    ->treatFalseLike([])
                    ->treatNullLike([])
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()
                        ->validate()
                            ->ifTrue(function ($config) {
                                return count($config) !== 1;
                            })
                            ->thenInvalid('One key type must be set.')
                        ->end()
                        ->children();
        foreach ($this->getJWKSources() as $name => $source) {
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
     * @return JWKSource[]
     */
    private function getJWKSources(): array
    {
        if (null !== $this->jwkSources) {
            return $this->jwkSources;
        }

        // load bundled adapter factories
        $tempContainer = new ContainerBuilder();
        $loader = new YamlFileLoader($tempContainer, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('jwk_sources.yml');
        $services = $tempContainer->findTaggedServiceIds('jose.jwk_source');
        $jwkSources = [];
        foreach (array_keys($services) as $id) {
            $factory = $tempContainer->get($id);
            $jwkSources[str_replace('-', '_', $factory->getKey())] = $factory;
        }

        $this->jwkSources = $jwkSources;

        return $jwkSources;
    }
}

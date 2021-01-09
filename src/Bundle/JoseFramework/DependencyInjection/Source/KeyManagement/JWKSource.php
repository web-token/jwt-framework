<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use function array_key_exists;
use function count;
use InvalidArgumentException;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource\JWKSource as JWKSourceInterface;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use LogicException;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

class JWKSource implements Source
{
    /**
     * @var null|JWKSourceInterface[]
     */
    private $jwkSources;

    public function name(): string
    {
        return 'keys';
    }

    /**
     * @throws LogicException if the definition is not configured
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $sources = $this->getJWKSources();
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            foreach ($itemConfig as $sourceName => $sourceConfig) {
                if (array_key_exists($sourceName, $sources)) {
                    $source = $sources[$sourceName];
                    $source->create($container, 'key', $name, $sourceConfig);
                } else {
                    throw new LogicException(sprintf('The JWK definition "%s" is not configured.', $name));
                }
            }
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        $sourceNodeBuilder = $node
            ->children()
            ->arrayNode('keys')
            ->treatFalseLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->validate()
            ->ifTrue(function ($config): bool {
                return 1 !== count($config);
            })
            ->thenInvalid('One key type must be set.')
            ->end()
            ->children()
        ;
        foreach ($this->getJWKSources() as $name => $source) {
            $sourceNode = $sourceNodeBuilder->arrayNode($name)->canBeUnset();
            $source->addConfiguration($sourceNode);
        }
    }

    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }

    /**
     * @throws InvalidArgumentException if the source object is invalid
     *
     * @return JWKSourceInterface[]
     */
    private function getJWKSources(): array
    {
        if (null !== $this->jwkSources) {
            return $this->jwkSources;
        }

        // load bundled adapter factories
        $tempContainer = new ContainerBuilder();
        $tempContainer->registerForAutoconfiguration(JWKSourceInterface::class)->addTag('jose.jwk_source');
        $loader = new PhpFileLoader($tempContainer, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('jwk_sources.php');
        $tempContainer->compile();

        $services = $tempContainer->findTaggedServiceIds('jose.jwk_source');
        $jwkSources = [];
        foreach (array_keys($services) as $id) {
            $factory = $tempContainer->get($id);
            if (!$factory instanceof JWKSourceInterface) {
                throw new InvalidArgumentException('Invalid object');
            }
            $jwkSources[str_replace('-', '_', $factory->getKey())] = $factory;
        }

        $this->jwkSources = $jwkSources;

        return $jwkSources;
    }
}

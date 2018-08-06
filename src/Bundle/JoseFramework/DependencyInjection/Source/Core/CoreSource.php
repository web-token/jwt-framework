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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Core;

use Jose\Bundle\JoseFramework\DataCollector\Collector;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\Converter\StandardConverter;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\EnvVarProcessorInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class CoreSource implements SourceWithCompilerPasses
{
    public function name(): string
    {
        return 'core';
    }

    public function load(array $config, ContainerBuilder $container)
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('services.yml');

        if (\interface_exists(EnvVarProcessorInterface::class)) {
            $loader->load('env_var.yml');
        }

        if (true === $container->getParameter('kernel.debug')) {
            $container->registerForAutoconfiguration(Collector::class)->addTag('jose.data_collector');
            $loader->load('dev_services.yml');
        }

        $container->setAlias(JsonConverter::class, $config['json_converter']);
        if (StandardConverter::class === $config['json_converter']) {
            $loader->load('json_converter.yml');
        }
    }

    public function getNodeDefinition(NodeDefinition $node)
    {
        $node
            ->children()
            ->scalarNode('json_converter')
            ->defaultValue(StandardConverter::class)
            ->info('Converter used to encode and decode JSON objects (JWT payloads, keys, key sets...).')
            ->end()
            ->end();
    }

    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }

    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array
    {
        return [
            new Compiler\AlgorithmCompilerPass(),
            new Compiler\DataCollectorCompilerPass(),
            new Compiler\CheckerCollectorCompilerPass(),
            new Compiler\KeyCollectorCompilerPass(),
            new Compiler\JWSCollectorCompilerPass(),
            new Compiler\JWECollectorCompilerPass(),
        ];
    }
}

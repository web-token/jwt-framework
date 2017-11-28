<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Config\FileLocator;

/**
 * Class JKUSource.
 */
final class JKUSource implements Source
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'jku_factory';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        if (true === $configs[$this->name()]['enabled']) {
            $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../Resources/config'));
            $loader->load('jku_source.yml');
            $loader->load('jku_commands.yml');
            $container->setAlias('jose.http_client', $configs[$this->name()]['client']);
            $container->setAlias('jose.request_factory', $configs[$this->name()]['request_factory']);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode('jku_factory')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('client')
                            ->info('HTTP Client used to retrieve key sets.')
                            ->isRequired()
                            ->defaultNull()
                        ->end()
                        ->scalarNode('request_factory')
                            ->isRequired()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config): ?array
    {
        return null;
    }
}

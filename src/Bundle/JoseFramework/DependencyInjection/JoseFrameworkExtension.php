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

namespace Jose\Bundle\JoseFramework\DependencyInjection;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class JoseFrameworkExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @var string
     */
    private $alias;

    /**
     * @var Source[]
     */
    private $sources = [];

    /**
     * JoseFrameworkExtension constructor.
     *
     * @param Source[] $sources
     */
    public function __construct(string $alias, array $sources)
    {
        $this->alias = $alias;
        $this->sources = $sources;
    }

    public function getAlias(): string
    {
        return $this->alias;
    }

    public function load(array $configs, ContainerBuilder $container)
    {
        $processor = new Processor();
        $config = $processor->processConfiguration($this->getConfiguration($configs, $container), $configs);

        foreach ($this->sources as $source) {
            $source->load($config, $container);
        }
    }

    public function getConfiguration(array $configs, ContainerBuilder $container): Configuration
    {
        return new Configuration($this->getAlias(), $this->sources);
    }

    public function prepend(ContainerBuilder $container)
    {
        $configs = $container->getExtensionConfig($this->getAlias());
        $config = $this->processConfiguration($this->getConfiguration($configs, $container), $configs);

        foreach ($this->sources as $source) {
            $result = $source->prepend($container, $config);
            if (!empty($result)) {
                $container->prependExtensionConfig($this->getAlias(), $result);
            }
        }
    }
}

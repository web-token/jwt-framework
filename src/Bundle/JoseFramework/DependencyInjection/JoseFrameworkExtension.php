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

namespace Jose\Bundle\JoseFramework\DependencyInjection;

use Jose\Bundle\JoseFramework\DependencyInjection\Source;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * Class JoseFrameworkExtension.
 */
final class JoseFrameworkExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @var string
     */
    private $alias;

    /**
     * @var Source\Source[]
     */
    private $sources = [];

    /**
     * JoseFrameworkExtension constructor.
     *
     * @param string $alias
     */
    public function __construct(string $alias)
    {
        $this->alias = $alias;
        $this->initSources();
    }

    /**
     * {@inheritdoc}
     */
    public function getAlias(): string
    {
        return $this->alias;
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $processor = new Processor();
        $config = $processor->processConfiguration($this->getConfiguration($configs, $container), $configs);

        foreach ($this->sources as $source) {
            $source->load($config, $container);
        }
    }

    /**
     * @param Source\Source $source
     */
    public function addSource(Source\Source $source)
    {
        $this->sources[ $source->name()] = $source;
    }

    /**
     * @param array            $configs
     * @param ContainerBuilder $container
     *
     * @return Configuration
     */
    public function getConfiguration(array $configs, ContainerBuilder $container): Configuration
    {
        return new Configuration($this->getAlias(), $this->sources);
    }

    private function initSources()
    {
        foreach ($this->getSources() as $class) {
            $this->addSource(new $class());
        }
    }

    /**
     * @return string[]
     */
    private function getSources(): array
    {
        return [
            Source\Core\CoreSource::class,
            Source\Checker\CheckerSource::class,
            Source\Encryption\EncryptionSource::class,
            Source\Console\ConsoleSource::class,
            Source\Signature\SignatureSource::class,
            Source\Encryption\EncryptionSource::class,
            Source\KeyManagement\KeyManagementSource::class,
        ];
    }

    /**
     * {@inheritdoc}
     */
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

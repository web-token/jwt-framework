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

use Http\HttplugBundle\HttplugBundle;
use Jose\Bundle\Checker\DependencyInjection\Source\ClaimChecker;
use Jose\Bundle\Checker\DependencyInjection\Source\HeaderChecker;
use Jose\Bundle\Encryption\DependencyInjection\Source\JWEBuilder;
use Jose\Bundle\Encryption\DependencyInjection\Source\JWELoader;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceInterface;
use Jose\Bundle\KeyManagement\DependencyInjection\Source\JKUSource;
use Jose\Bundle\KeyManagement\DependencyInjection\Source\JWKSetSource;
use Jose\Bundle\KeyManagement\DependencyInjection\Source\JWKSource;
use Jose\Bundle\Signature\DependencyInjection\Source\JWSBuilder;
use Jose\Bundle\Signature\DependencyInjection\Source\JWSLoader;
use Jose\Component\Core\Converter\JsonConverterInterface;
use Jose\Component\Core\Converter\StandardJsonConverter;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
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
     * @var SourceInterface[]
     */
    private $serviceSources = [];

    /**
     * JoseFrameworkExtension constructor.
     *
     * @param string $alias
     */
    public function __construct(string $alias)
    {
        $this->alias = $alias;
        $this->addDefaultSources();
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

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yml');

        $container->setAlias(JsonConverterInterface::class, $config['json_converter']);
        if (StandardJsonConverter::class === $config['json_converter']) {
            $loader->load('json_converter.yml');
        }

        foreach ($this->serviceSources as $serviceSource) {
            $serviceSource->load($config, $container);
        }
    }

    /**
     * @param SourceInterface $source
     */
    public function addSource(SourceInterface $source)
    {
        $name = $source->name();
        if (in_array($name, $this->serviceSources)) {
            throw new \InvalidArgumentException(sprintf('The source "%s" is already set.', $name));
        }
        $this->serviceSources[$name] = $source;
    }

    /**
     * @param array            $configs
     * @param ContainerBuilder $container
     *
     * @return Configuration
     */
    public function getConfiguration(array $configs, ContainerBuilder $container): Configuration
    {
        return new Configuration($this->getAlias(), $this->serviceSources);
    }

    private function addDefaultSources()
    {
        if (class_exists(JKUSource::class) && class_exists(HttplugBundle::class)) {
            $this->addSource(new JKUSource());
        }
        if (class_exists(JWKSource::class)) {
            $this->addSource(new JWKSource());
        }
        if (class_exists(JWKSetSource::class)) {
            $this->addSource(new JWKSetSource());
        }
        if (class_exists(ClaimChecker::class)) {
            $this->addSource(new ClaimChecker());
        }
        if (class_exists(HeaderChecker::class)) {
            $this->addSource(new HeaderChecker());
        }
        if (class_exists(JWSBuilder::class)) {
            $this->addSource(new JWSBuilder());
        }
        if (class_exists(JWSLoader::class)) {
            $this->addSource(new JWSLoader());
        }
        if (class_exists(JWEBuilder::class)) {
            $this->addSource(new JWEBuilder());
        }
        if (class_exists(JWELoader::class)) {
            $this->addSource(new JWELoader());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container)
    {
        $configs = $container->getExtensionConfig($this->getAlias());
        $config = $this->processConfiguration($this->getConfiguration($configs, $container), $configs);

        foreach ($this->serviceSources as $serviceSource) {
            $result = $serviceSource->prepend($container, $config);
            if (null !== $result) {
                $container->prependExtensionConfig($this->getAlias(), $result);
            }
        }
    }
}

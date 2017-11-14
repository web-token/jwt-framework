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
use Jose\Bundle\Encryption\DependencyInjection\Source\JWEDecrypter;
use Jose\Bundle\Encryption\DependencyInjection\Source\JWESerializer;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\KeyManagement\DependencyInjection\Source\JKUSource;
use Jose\Bundle\KeyManagement\DependencyInjection\Source\JWKUriSource;
use Jose\Bundle\KeyManagement\DependencyInjection\Source\JWKSetSource;
use Jose\Bundle\KeyManagement\DependencyInjection\Source\JWKSource;
use Jose\Bundle\Signature\DependencyInjection\Source\JWSBuilder;
use Jose\Bundle\Signature\DependencyInjection\Source\JWSSerializer;
use Jose\Bundle\Signature\DependencyInjection\Source\JWSVerifier;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\Converter\StandardConverter;
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
     * @var Source[]
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
        if (true === $container->getParameter('kernel.debug')) {
            $loader->load('dev_services.yml');
        }

        $container->setAlias(JsonConverter::class, $config['json_converter']);
        if (StandardConverter::class === $config['json_converter']) {
            $loader->load('json_converter.yml');
        }

        foreach ($this->serviceSources as $serviceSource) {
            $serviceSource->load($config, $container);
        }
    }

    /**
     * @param Source $source
     */
    public function addSource(Source $source)
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
        if (class_exists(JWKUriSource::class)) {
            $this->addSource(new JWKUriSource());
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
        if (class_exists(JWSSerializer::class)) {
            $this->addSource(new JWSSerializer());
        }
        if (class_exists(JWSVerifier::class)) {
            $this->addSource(new JWSVerifier());
        }
        if (class_exists(JWEBuilder::class)) {
            $this->addSource(new JWEBuilder());
        }
        if (class_exists(JWEDecrypter::class)) {
            $this->addSource(new JWEDecrypter());
        }
        if (class_exists(JWESerializer::class)) {
            $this->addSource(new JWESerializer());
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

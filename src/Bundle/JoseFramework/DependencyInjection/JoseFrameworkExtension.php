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
use Jose\Bundle\JoseFramework\DependencyInjection\Source as ModuleSource;
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
     * @var ModuleSource\Source[]
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

        $this->loadOtherExtensions($container);
    }

    /**
     * @param ContainerBuilder $container
     */
    private function loadOtherExtensions(ContainerBuilder $container)
    {
        foreach ($this->otherExtensionList() as $class) {
            if (!class_exists($class)) {
                continue;
            }
            $extension = new $class();
            $extension->load($container);
        }
    }

    /**
     * @return string[]
     */
    private function otherExtensionList(): array
    {
        return [
            CheckerExtension::class,
            ConsoleExtension::class,
            EncryptionExtension::class,
            KeyManagementExtension::class,
            SignatureExtension::class,
        ];
    }

    /**
     * @param ModuleSource\Source $source
     */
    public function addSource(ModuleSource\Source $source)
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
        if (class_exists(ModuleSource\JKUSource::class) && class_exists(HttplugBundle::class)) {
            $this->addSource(new ModuleSource\JKUSource());
        }
        foreach ($this->getSourceClasses() as $class) {
            if (class_exists($class)) {
                $this->addSource(new $class());
            }
        }
    }

    /**
     * @return string[]
     */
    private function getSourceClasses(): array
    {
        return [
            ModuleSource\JWKSource::class,
            ModuleSource\JWKUriSource::class,
            ModuleSource\JWKSetSource::class,
            ModuleSource\ClaimChecker::class,
            ModuleSource\HeaderChecker::class,
            ModuleSource\JWSBuilder::class,
            ModuleSource\JWSSerializer::class,
            ModuleSource\JWSVerifier::class,
            ModuleSource\JWEBuilder::class,
            ModuleSource\JWEDecrypter::class,
            ModuleSource\JWESerializer::class,
        ];
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

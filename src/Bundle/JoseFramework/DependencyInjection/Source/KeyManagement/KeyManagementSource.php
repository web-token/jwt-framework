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

use Http\HttplugBundle\HttplugBundle;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * Class KeyManagementSource.
 */
final class KeyManagementSource implements Source
{
    /**
     * @var Source[]
     */
    private $sources;

    /**
     * KeyManagementSource constructor.
     */
    public function __construct()
    {
        $this->sources = [
            new JWKSetSource(),
            new JWKSource(),
            new JWKUriSource(),
        ];
        if (class_exists(HttplugBundle::class)) {
            $this->sources[] = new JKUSource();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'key_mgmt';
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        if (!$this->isEnabled()) {
            return;
        }
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('analyzers.yml');
        $loader->load('jwk_factory.yml');
        $loader->load('jwk_services.yml');

        foreach ($this->sources as $source) {
            $source->load($configs, $container);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getNodeDefinition(ArrayNodeDefinition $node)
    {
        if (!$this->isEnabled()) {
            return;
        }
        foreach ($this->sources as $source) {
            $source->getNodeDefinition($node);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container, array $config): array
    {
        if (!$this->isEnabled()) {
            return [];
        }
        $result = [];
        foreach ($this->sources as $source) {
            $prepend = $source->prepend($container, $config);
            if (!empty($prepend)) {
                $result[$source->name()] = $prepend;
            }
        }

        return $result;
    }

    /**
     * @return bool
     */
    private function isEnabled(): bool
    {
        return class_exists(JWKFactory::class);
    }

    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array
    {
        return [
            new Compiler\KeyAnalyzerCompilerPass(),
            new Compiler\KeySetControllerCompilerPass(),
        ];
    }
}

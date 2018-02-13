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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Encryption;

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * Class EncryptionSource.
 */
final class EncryptionSource implements Source
{
    /**
     * @var Source[]
     */
    private $sources;

    /**
     * EncryptionSource constructor.
     */
    public function __construct()
    {
        $this->sources = [
            new JWEBuilder(),
            new JWEDecrypter(),
            new JWESerializer(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'jwe';
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
        $loader->load('jwe_services.yml');
        $loader->load('encryption_algorithms.yml');
        $loader->load('jwe_serializers.yml');
        $loader->load('compression_methods.yml');

        if (array_key_exists('jwe', $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs['jwe'], $container);
            }
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
        $childNode = $node
            ->children()
                ->arrayNode($this->name())
            ->addDefaultsIfNotSet()
            ->treatFalseLike([])
                    ->treatNullLike([]);

        foreach ($this->sources as $source) {
            $source->getNodeDefinition($childNode);
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
        return class_exists(JWEBuilderFactory::class) && class_exists(JWEDecrypterFactory::class);
    }

    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array
    {
        return [
            new Compiler\EncryptionSerializerCompilerPass(),
            new Compiler\CompressionMethodCompilerPass(),
        ];
    }
}

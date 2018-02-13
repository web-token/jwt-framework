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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature;

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSVerifierFactory;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * Class SignatureSource.
 */
final class SignatureSource implements Source
{
    /**
     * @var Source[]
     */
    private $sources;

    /**
     * SignatureSource constructor.
     */
    public function __construct()
    {
        $this->sources = [
            new JWSBuilder(),
            new JWSVerifier(),
            new JWSSerializer(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'jws';
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
        $loader->load('jws_services.yml');
        $loader->load('jws_serializers.yml');
        $loader->load('signature_algorithms.yml');

        if (array_key_exists('jws', $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs['jws'], $container);
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
        return class_exists(JWSBuilderFactory::class) && class_exists(JWSVerifierFactory::class);
    }

    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array
    {
        return [
            new Compiler\SignatureSerializerCompilerPass(),
        ];
    }
}

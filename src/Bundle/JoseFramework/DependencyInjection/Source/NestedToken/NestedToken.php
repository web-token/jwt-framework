<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\NestedToken;

use function array_key_exists;
use function count;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\NestedToken\NestedTokenBuilder as JoseNestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenLoader as JoseNestedTokenLoader;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

class NestedToken implements Source
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
            new NestedTokenLoader(),
            new NestedTokenBuilder(),
        ];
    }

    public function name(): string
    {
        return 'nested_token';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        if (!$this->isEnabled()) {
            return;
        }
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('nested_token.php');

        if (array_key_exists('nested_token', $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs['nested_token'], $container);
            }
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        if (!$this->isEnabled()) {
            return;
        }
        $childNode = $node->children()
            ->arrayNode($this->name())
            ->treatNullLike([])
            ->treatFalseLike([])
        ;

        foreach ($this->sources as $source) {
            $source->getNodeDefinition($childNode);
        }
    }

    public function prepend(ContainerBuilder $container, array $config): array
    {
        if (!$this->isEnabled()) {
            return [];
        }
        $result = [];
        foreach ($this->sources as $source) {
            $prepend = $source->prepend($container, $config);
            if (0 !== count($prepend)) {
                $result[$source->name()] = $prepend;
            }
        }

        return $result;
    }

    private function isEnabled(): bool
    {
        return class_exists(JoseNestedTokenBuilder::class)
            && class_exists(JoseNestedTokenLoader::class);
    }
}

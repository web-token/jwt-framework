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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker;

use function array_key_exists;
use function count;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\TokenTypeSupport;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

class CheckerSource implements SourceWithCompilerPasses
{
    /**
     * @var Source[]
     */
    private $sources;

    /**
     * CheckerSource constructor.
     */
    public function __construct()
    {
        $this->sources = [
            new ClaimChecker(),
            new HeaderChecker(),
        ];
    }

    public function name(): string
    {
        return 'checkers';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        if (!$this->isEnabled()) {
            return;
        }
        $container->registerForAutoconfiguration(TokenTypeSupport::class)->addTag('jose.checker.token_type');
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('checkers.php');

        if (array_key_exists('checkers', $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs['checkers'], $container);
            }
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        if (!$this->isEnabled()) {
            return;
        }
        $childNode = $node
            ->children()
            ->arrayNode($this->name())
            ->addDefaultsIfNotSet()
            ->treatFalseLike([])
            ->treatNullLike([])
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

    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array
    {
        return [
            new Compiler\ClaimCheckerCompilerPass(),
            new Compiler\HeaderCheckerCompilerPass(),
        ];
    }

    private function isEnabled(): bool
    {
        return class_exists(HeaderCheckerManagerFactory::class) && class_exists(ClaimCheckerManagerFactory::class);
    }
}

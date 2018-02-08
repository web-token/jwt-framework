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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Console;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Jose\Component\Console\EcKeyGeneratorCommand;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
  * Class ConsoleSource.
  */
 class ConsoleSource implements SourceWithCompilerPasses
 {
     /**
      * {@inheritdoc}
      */
     public function name(): string
     {
         return 'console';
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
         $loader->load('commands.yml');
     }

     /**
      * {@inheritdoc}
      */
     public function getNodeDefinition(NodeDefinition $node)
     {
     }

     /**
      * {@inheritdoc}
      */
     public function prepend(ContainerBuilder $container, array $config): array
     {
         return [];
     }

     /**
      * @return bool
      */
     private function isEnabled(): bool
     {
         return class_exists(EcKeyGeneratorCommand::class);
     }

     /**
      * @return CompilerPassInterface[]
      */
     public function getCompilerPasses(): array
     {
         return [
        ];
     }
 }

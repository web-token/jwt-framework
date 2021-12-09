<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Core;

use Jose\Bundle\JoseFramework\DataCollector\Collector;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\AlgorithmCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\CheckerCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\DataCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\JWECollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\JWSCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\KeyCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\EnvVarProcessorInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

class CoreSource implements SourceWithCompilerPasses
{
    public function name(): string
    {
        return 'core';
    }

    public function load(array $config, ContainerBuilder $container): void
    {
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config'));
        $loader->load('services.php');

        if (interface_exists(EnvVarProcessorInterface::class)) {
            $loader->load('env_var.php');
        }

        if ($container->getParameter('kernel.debug') === true) {
            $container->registerForAutoconfiguration(Collector::class)->addTag('jose.data_collector');
            $loader->load('dev_services.php');
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
    }

    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }

    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array
    {
        return [
            new AlgorithmCompilerPass(),
            new DataCollectorCompilerPass(),
            new CheckerCollectorCompilerPass(),
            new KeyCollectorCompilerPass(),
            new JWSCollectorCompilerPass(),
            new JWECollectorCompilerPass(),
        ];
    }
}

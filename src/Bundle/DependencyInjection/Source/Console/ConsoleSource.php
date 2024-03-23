<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Console;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

final readonly class ConsoleSource implements Source
{
    #[Override]
    public function name(): string
    {
        return 'console';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config'));
        $loader->load('commands.php');
    }

    #[Override]
    public function getNodeDefinition(NodeDefinition $node): void
    {
        // No configuration needed
    }

    #[Override]
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

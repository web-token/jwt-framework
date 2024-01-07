<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\Console\JKULoaderCommand;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

class JKUSource implements Source
{
    public function name(): string
    {
        return 'jku_factory';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        if ($configs[$this->name()]['enabled'] === true) {
            $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config'));
            $loader->load('jku_source.php');
            if (class_exists(JKULoaderCommand::class)) {
                $loader->load('jku_commands.php');
            }
            $container->setAlias('jose.http_client', $configs[$this->name()]['client']);
            $container->setAlias('jose.request_factory', $configs[$this->name()]['request_factory']);
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node
            ->children()
            ->arrayNode('jku_factory')
            ->canBeEnabled()
            ->children()
            ->scalarNode('client')
            ->info('HTTP Client used to retrieve key sets.')
            ->isRequired()
            ->defaultNull()
            ->end()
            ->scalarNode('request_factory')
            ->info('The request factory service.')
            ->isRequired()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

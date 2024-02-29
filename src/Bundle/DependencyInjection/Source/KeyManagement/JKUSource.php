<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

final readonly class JKUSource implements Source
{
    #[Override]
    public function name(): string
    {
        return 'jku_factory';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        if ($configs[$this->name()]['enabled'] === true) {
            $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config'));
            $loader->load('jku_source.php');
            $loader->load('jku_commands.php');
            $container->setAlias('jose.http_client', $configs[$this->name()]['client']);
            if (isset($configs[$this->name()]['request_factory'])) {
                $container->setAlias('jose.request_factory', $configs[$this->name()]['request_factory']);
            }
        }
    }

    #[Override]
    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node->children()
            ->arrayNode('jku_factory')
            ->canBeEnabled()
            ->children()
            ->scalarNode('client')
            ->info('HTTP Client used to retrieve key sets.')
            ->isRequired()
            ->end()
            ->scalarNode('request_factory')
            ->info('The request factory service.')
            //->setDeprecated('The "%node%" option is deprecated and will be removed in 4.0.')
            ->defaultNull()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    #[Override]
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }
}

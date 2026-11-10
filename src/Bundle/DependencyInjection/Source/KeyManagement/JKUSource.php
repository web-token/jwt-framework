<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\X5UFactory;
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
            $followRedirects = $configs[$this->name()]['follow_redirects'] ?? null;
            $allowLargeKeySets = $configs[$this->name()]['allow_large_key_sets'] ?? null;
            if ($followRedirects !== null || $allowLargeKeySets !== null) {
                foreach ([JKUFactory::class, X5UFactory::class] as $factory) {
                    $definition = $container->getDefinition($factory)
                        ->addArgument($followRedirects);
                    if ($allowLargeKeySets !== null) {
                        $definition->addArgument($allowLargeKeySets);
                    }
                }
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
            ->booleanNode('allow_large_key_sets')
            ->info(
                'True loads the key sets of more than 4096 JSON values, false refuses them. When it is not set, they are loaded with a deprecation, as 5.0.0 refuses them by default.'
            )
            ->end()
            ->booleanNode('follow_redirects')
            ->info(
                'False refuses the redirects of the key set URLs, true follows them. When it is not set, they are followed with a deprecation, as 5.0.0 refuses them by default.'
            )
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

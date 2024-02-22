<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker;

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\ClaimCheckerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\HeaderCheckerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Jose\Component\Checker\TokenTypeSupport;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use function array_key_exists;
use function count;

class CheckerSource implements SourceWithCompilerPasses
{
    /**
     * @var Source[]
     */
    private readonly array $sources;

    public function __construct()
    {
        $this->sources = [new ClaimChecker(), new HeaderChecker()];
    }

    public function name(): string
    {
        return 'checkers';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $container->registerForAutoconfiguration(TokenTypeSupport::class)->addTag('jose.checker.token_type');
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config'));
        $loader->load('checkers.php');

        $container->setAlias('jose.clock', $configs['clock']);
        if (array_key_exists('checkers', $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs['checkers'], $container);
            }
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node->children()
            ->scalarNode('clock')
            ->defaultValue('jose.internal_clock')
            ->cannotBeEmpty()
            ->info('PSR-20 clock')
            ->end()
            ->end();
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

    public function prepend(ContainerBuilder $container, array $config): array
    {
        $result = [];
        foreach ($this->sources as $source) {
            $prepend = $source->prepend($container, $config);
            if (count($prepend) !== 0) {
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
        return [new ClaimCheckerCompilerPass(), new HeaderCheckerCompilerPass()];
    }
}

<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement;

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\KeyAnalyzerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\KeysetAnalyzerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\KeySetControllerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzer;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use function count;

final readonly class KeyManagementSource implements SourceWithCompilerPasses
{
    /**
     * @var Source[]
     */
    private readonly array $sources;

    public function __construct()
    {
        $this->sources = [new JWKSetSource(), new JWKSource(), new JWKUriSource(), new JKUSource()];
    }

    #[Override]
    public function name(): string
    {
        return 'key_mgmt';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        $container->registerForAutoconfiguration(KeyAnalyzer::class)->addTag('jose.key_analyzer');
        $container->registerForAutoconfiguration(KeysetAnalyzer::class)->addTag('jose.keyset_analyzer');
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config'));
        $loader->load('analyzers.php');
        $loader->load('jwk_factory.php');
        $loader->load('jwk_services.php');

        foreach ($this->sources as $source) {
            $source->load($configs, $container);
        }
    }

    #[Override]
    public function getNodeDefinition(NodeDefinition $node): void
    {
        foreach ($this->sources as $source) {
            $source->getNodeDefinition($node);
        }
    }

    #[Override]
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
    #[Override]
    public function getCompilerPasses(): array
    {
        return [
            new KeyAnalyzerCompilerPass(),
            new KeysetAnalyzerCompilerPass(),
            new KeySetControllerCompilerPass(),
        ];
    }
}

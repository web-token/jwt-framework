<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\NestedToken;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use function array_key_exists;
use function count;

class NestedToken implements Source
{
    /**
     * @var Source[]
     */
    private readonly array $sources;

    public function __construct()
    {
        $this->sources = [new NestedTokenLoader(), new NestedTokenBuilder()];
    }

    public function name(): string
    {
        return 'nested_token';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config'));
        $loader->load('nested_token.php');

        if (array_key_exists('nested_token', $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs['nested_token'], $container);
            }
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        $childNode = $node->children()
            ->arrayNode($this->name())
            ->treatNullLike([])
            ->treatFalseLike([]);

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
}

<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\SelectiveDisclosure;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use function array_key_exists;
use function count;

/**
 * The services of the three roles of RFC 9901, Selective Disclosure for JSON Web Tokens: the Issuers, the Holders and
 * the Verifiers declared under "jose.selective_disclosure".
 */
final readonly class SelectiveDisclosure implements Source
{
    /**
     * @var Source[]
     */
    private array $sources;

    public function __construct()
    {
        $this->sources = [new SDJWTIssuer(), new SDJWTHolder(), new SDJWTVerifier()];
    }

    #[Override]
    public function name(): string
    {
        return 'selective_disclosure';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config'));
        $loader->load('selective_disclosure.php');

        if (array_key_exists($this->name(), $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs[$this->name()], $container);
            }
        }
    }

    #[Override]
    public function getNodeDefinition(NodeDefinition $node): void
    {
        $childNode = $node->children()
            ->arrayNode($this->name())
            ->addDefaultsIfNotSet()
            ->treatNullLike([])
            ->treatFalseLike([]);

        foreach ($this->sources as $source) {
            $source->getNodeDefinition($childNode);
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
}

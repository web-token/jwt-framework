<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature;

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\SignatureSerializerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Jose\Component\Signature\Algorithm\ECDSA;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\HMAC;
use Jose\Component\Signature\Algorithm\HS1;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\RSAPSS;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use function array_key_exists;
use function count;
use function extension_loaded;

class SignatureSource implements SourceWithCompilerPasses
{
    /**
     * @var Source[]
     */
    private readonly array $sources;

    public function __construct()
    {
        $this->sources = [new JWSBuilder(), new JWSVerifier(), new JWSSerializer(), new JWSLoader()];
    }

    public function name(): string
    {
        return 'jws';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $container->registerForAutoconfiguration(\Jose\Component\Signature\Serializer\JWSSerializer::class)->addTag(
            'jose.jws.serializer'
        );
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config/'));
        $loader->load('jws_services.php');
        $loader->load('jws_serializers.php');

        $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../../../Resources/config/Algorithms/'));
        foreach ($this->getAlgorithmsFiles() as $class => $file) {
            if (class_exists($class)) {
                $loader->load($file);
            }
        }

        if (array_key_exists('jws', $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs['jws'], $container);
            }
        }
    }

    public function getNodeDefinition(NodeDefinition $node): void
    {
        $childNode = $node->children()
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
        return [new SignatureSerializerCompilerPass()];
    }

    private function getAlgorithmsFiles(): array
    {
        $algorithms = [
            ECDSA::class => 'signature_ecdsa.php',
            HMAC::class => 'signature_hmac.php',
            None::class => 'signature_none.php',
            HS1::class => 'signature_experimental.php',
            RSAPSS::class => 'signature_rsa.php',
        ];

        if (extension_loaded('sodium')) {
            $algorithms[EdDSA::class] = 'signature_eddsa.php';
        }

        return $algorithms;
    }
}

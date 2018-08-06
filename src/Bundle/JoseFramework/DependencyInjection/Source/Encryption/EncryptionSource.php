<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Encryption;

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SourceWithCompilerPasses;
use Jose\Component\Encryption\Algorithm\ContentEncryption\AESCBCHS;
use Jose\Component\Encryption\Algorithm\ContentEncryption\AESGCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128CTR;
use Jose\Component\Encryption\Algorithm\KeyEncryption\AESGCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\AESKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Chacha20Poly1305;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2AESKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class EncryptionSource implements SourceWithCompilerPasses
{
    /**
     * @var Source[]
     */
    private $sources;

    /**
     * EncryptionSource constructor.
     */
    public function __construct()
    {
        $this->sources = [
            new JWEBuilder(),
            new JWEDecrypter(),
            new JWESerializer(),
            new JWELoader(),
        ];
    }

    public function name(): string
    {
        return 'jwe';
    }

    public function load(array $configs, ContainerBuilder $container)
    {
        if (!$this->isEnabled()) {
            return;
        }
        $container->registerForAutoconfiguration(\Jose\Component\Encryption\Serializer\JWESerializer::class)->addTag('jose.jwe.serializer');
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../../Resources/config'));
        $loader->load('jwe_services.yml');
        $loader->load('jwe_serializers.yml');
        $loader->load('compression_methods.yml');

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../../Resources/config/Algorithms/'));
        foreach ($this->getAlgorithmsFiles() as $class => $file) {
            if (\class_exists($class)) {
                $loader->load($file);
            }
        }

        if (\array_key_exists('jwe', $configs)) {
            foreach ($this->sources as $source) {
                $source->load($configs['jwe'], $container);
            }
        }
    }

    private function getAlgorithmsFiles(): array
    {
        $list = [
            AESCBCHS::class => 'encryption_aescbc.yml',
            AESGCM::class => 'encryption_aesgcm.yml',
            AESGCMKW::class => 'encryption_aesgcmkw.yml',
            AESKW::class => 'encryption_aeskw.yml',
            Dir::class => 'encryption_dir.yml',
            ECDHES::class => 'encryption_ecdhes.yml',
            PBES2AESKW::class => 'encryption_pbes2.yml',
            RSA::class => 'encryption_rsa.yml',
            A128CTR::class => 'encryption_experimental.yml',
        ];
        if (\in_array('chacha20-poly1305', \openssl_get_cipher_methods(), true)) {
            $list[Chacha20Poly1305::class] = 'encryption_experimental_chacha20_poly1305.yml';
        }

        return $list;
    }

    public function getNodeDefinition(NodeDefinition $node)
    {
        if (!$this->isEnabled()) {
            return;
        }
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
        if (!$this->isEnabled()) {
            return [];
        }
        $result = [];
        foreach ($this->sources as $source) {
            $prepend = $source->prepend($container, $config);
            if (!empty($prepend)) {
                $result[$source->name()] = $prepend;
            }
        }

        return $result;
    }

    private function isEnabled(): bool
    {
        return \class_exists(JWEBuilderFactory::class) && \class_exists(JWEDecrypterFactory::class);
    }

    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array
    {
        return [
            new Compiler\EncryptionSerializerCompilerPass(),
            new Compiler\CompressionMethodCompilerPass(),
        ];
    }
}

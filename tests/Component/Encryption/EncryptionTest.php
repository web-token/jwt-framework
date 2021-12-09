<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use PHPUnit\Framework\TestCase;

abstract class EncryptionTest extends TestCase
{
    private ?AlgorithmManagerFactory $algorithmManagerFactory = null;

    private ?CompressionMethodManagerFactory $compressionMethodManagerFactory = null;

    private ?JWEBuilderFactory $jweBuilderFactory = null;

    private ?JWEDecrypterFactory $jweDecrypterFactory = null;

    private ?JWELoaderFactory $jweLoaderFactory = null;

    private ?JWESerializerManagerFactory $jwsSerializerManagerFactory = null;

    private ?JWESerializerManager $jwsSerializerManager = null;

    protected function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if ($this->algorithmManagerFactory === null) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory->add('A128GCM', new A128GCM());
            $this->algorithmManagerFactory->add('A192GCM', new A192GCM());
            $this->algorithmManagerFactory->add('A256GCM', new A256GCM());
            $this->algorithmManagerFactory->add('A128CBC-HS256', new A128CBCHS256());
            $this->algorithmManagerFactory->add('A192CBC-HS384', new A192CBCHS384());
            $this->algorithmManagerFactory->add('A256CBC-HS512', new A256CBCHS512());
            $this->algorithmManagerFactory->add('A128GCMKW', new A128GCMKW());
            $this->algorithmManagerFactory->add('A192GCMKW', new A192GCMKW());
            $this->algorithmManagerFactory->add('A256GCMKW', new A256GCMKW());
            $this->algorithmManagerFactory->add('A128KW', new A128KW());
            $this->algorithmManagerFactory->add('A192KW', new A192KW());
            $this->algorithmManagerFactory->add('A256KW', new A256KW());
            $this->algorithmManagerFactory->add('dir', new Dir());
            $this->algorithmManagerFactory->add('ECDH-ES', new ECDHES());
            $this->algorithmManagerFactory->add('ECDH-ES+A128KW', new ECDHESA128KW());
            $this->algorithmManagerFactory->add('ECDH-ES+A192KW', new ECDHESA192KW());
            $this->algorithmManagerFactory->add('ECDH-ES+A256KW', new ECDHESA256KW());
            $this->algorithmManagerFactory->add('PBES2-HS256+A128KW', new PBES2HS256A128KW());
            $this->algorithmManagerFactory->add('PBES2-HS384+A192KW', new PBES2HS384A192KW());
            $this->algorithmManagerFactory->add('PBES2-HS512+A256KW', new PBES2HS512A256KW());
            $this->algorithmManagerFactory->add('RSA1_5', new RSA15());
            $this->algorithmManagerFactory->add('RSA-OAEP', new RSAOAEP());
            $this->algorithmManagerFactory->add('RSA-OAEP-256', new RSAOAEP256());
        }

        return $this->algorithmManagerFactory;
    }

    protected function getCompressionMethodManagerFactory(): CompressionMethodManagerFactory
    {
        if ($this->compressionMethodManagerFactory === null) {
            $this->compressionMethodManagerFactory = new CompressionMethodManagerFactory();
            $this->compressionMethodManagerFactory->add('DEF', new Deflate());
        }

        return $this->compressionMethodManagerFactory;
    }

    protected function getJWEBuilderFactory(): JWEBuilderFactory
    {
        if ($this->jweBuilderFactory === null) {
            $this->jweBuilderFactory = new JWEBuilderFactory(
                $this->getAlgorithmManagerFactory(),
                $this->getCompressionMethodManagerFactory()
            );
        }

        return $this->jweBuilderFactory;
    }

    protected function getJWEDecrypterFactory(): JWEDecrypterFactory
    {
        if ($this->jweDecrypterFactory === null) {
            $this->jweDecrypterFactory = new JWEDecrypterFactory(
                $this->getAlgorithmManagerFactory(),
                $this->getCompressionMethodManagerFactory()
            );
        }

        return $this->jweDecrypterFactory;
    }

    protected function getJWELoaderFactory(): JWELoaderFactory
    {
        if ($this->jweLoaderFactory === null) {
            $this->jweLoaderFactory = new JWELoaderFactory(
                $this->getJWESerializerManagerFactory(),
                $this->getJWEDecrypterFactory(),
                null
            );
        }

        return $this->jweLoaderFactory;
    }

    protected function getJWESerializerManagerFactory(): JWESerializerManagerFactory
    {
        if ($this->jwsSerializerManagerFactory === null) {
            $this->jwsSerializerManagerFactory = new JWESerializerManagerFactory();
            $this->jwsSerializerManagerFactory->add(new CompactSerializer());
            $this->jwsSerializerManagerFactory->add(new JSONFlattenedSerializer());
            $this->jwsSerializerManagerFactory->add(new JSONGeneralSerializer());
        }

        return $this->jwsSerializerManagerFactory;
    }

    protected function getJWESerializerManager(): JWESerializerManager
    {
        if ($this->jwsSerializerManager === null) {
            $this->jwsSerializerManager = new JWESerializerManager([
                new CompactSerializer(),
                new JSONFlattenedSerializer(),
                new JSONGeneralSerializer(),
            ]);
        }

        return $this->jwsSerializerManager;
    }
}

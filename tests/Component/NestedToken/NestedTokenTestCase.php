<?php

declare(strict_types=1);

namespace Jose\Tests\Component\NestedToken;

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
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use PHPUnit\Framework\TestCase;

abstract class NestedTokenTestCase extends TestCase
{
    private ?AlgorithmManagerFactory $algorithmManagerFactory = null;

    private ?JWEBuilderFactory $jweBuilderFactory = null;

    private ?JWEDecrypterFactory $jweDecrypterFactory = null;

    private ?JWELoaderFactory $jweLoaderFactory = null;

    private ?JWESerializerManagerFactory $jwsSerializerManagerFactory = null;

    private ?JWESerializerManager $jwsSerializerManager = null;

    protected function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if ($this->algorithmManagerFactory === null) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory([
                new A128GCM(),
                new A192GCM(),
                new A256GCM(),
                new A128CBCHS256(),
                new A192CBCHS384(),
                new A256CBCHS512(),
                new A128GCMKW(),
                new A192GCMKW(),
                new A256GCMKW(),
                new A128KW(),
                new A192KW(),
                new A256KW(),
                new Dir(),
                new ECDHES(),
                new ECDHESA128KW(),
                new ECDHESA192KW(),
                new ECDHESA256KW(),
                new PBES2HS256A128KW(),
                new PBES2HS384A192KW(),
                new PBES2HS512A256KW(),
                new RSA15(),
                new RSAOAEP(),
                new RSAOAEP256(),
            ]);
        }
        return $this->algorithmManagerFactory;
    }

    protected function getJWEBuilderFactory(): JWEBuilderFactory
    {
        if ($this->jweBuilderFactory === null) {
            $this->jweBuilderFactory = new JWEBuilderFactory($this->getAlgorithmManagerFactory());
        }
        return $this->jweBuilderFactory;
    }

    protected function getJWEDecrypterFactory(): JWEDecrypterFactory
    {
        if ($this->jweDecrypterFactory === null) {
            $this->jweDecrypterFactory = new JWEDecrypterFactory($this->getAlgorithmManagerFactory());
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

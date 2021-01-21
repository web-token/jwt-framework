<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\NestedToken;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Jose\Component\Encryption\Compression;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Encryption\Serializer;
use PHPUnit\Framework\TestCase;

abstract class NestedTokenTest extends TestCase
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var CompressionMethodManagerFactory
     */
    private $compressionMethodManagerFactory;

    /**
     * @var JWEBuilderFactory
     */
    private $jweBuilderFactory;

    /**
     * @var JWEDecrypterFactory
     */
    private $jweDecrypterFactory;

    /**
     * @var JWELoaderFactory
     */
    private $jweLoaderFactory;

    /**
     * @var null|Serializer\JWESerializerManagerFactory
     */
    private $jwsSerializerManagerFactory;

    /**
     * @var null|Serializer\JWESerializerManager
     */
    private $jwsSerializerManager;

    protected function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (null === $this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory->add('A128GCM', new ContentEncryption\A128GCM());
            $this->algorithmManagerFactory->add('A192GCM', new ContentEncryption\A192GCM());
            $this->algorithmManagerFactory->add('A256GCM', new ContentEncryption\A256GCM());
            $this->algorithmManagerFactory->add('A128CBC-HS256', new ContentEncryption\A128CBCHS256());
            $this->algorithmManagerFactory->add('A192CBC-HS384', new ContentEncryption\A192CBCHS384());
            $this->algorithmManagerFactory->add('A256CBC-HS512', new ContentEncryption\A256CBCHS512());
            $this->algorithmManagerFactory->add('A128GCMKW', new KeyEncryption\A128GCMKW());
            $this->algorithmManagerFactory->add('A192GCMKW', new KeyEncryption\A192GCMKW());
            $this->algorithmManagerFactory->add('A256GCMKW', new KeyEncryption\A256GCMKW());
            $this->algorithmManagerFactory->add('A128KW', new KeyEncryption\A128KW());
            $this->algorithmManagerFactory->add('A192KW', new KeyEncryption\A192KW());
            $this->algorithmManagerFactory->add('A256KW', new KeyEncryption\A256KW());
            $this->algorithmManagerFactory->add('dir', new KeyEncryption\Dir());
            $this->algorithmManagerFactory->add('ECDH-ES', new KeyEncryption\ECDHES());
            $this->algorithmManagerFactory->add('ECDH-ES+A128KW', new KeyEncryption\ECDHESA128KW());
            $this->algorithmManagerFactory->add('ECDH-ES+A192KW', new KeyEncryption\ECDHESA192KW());
            $this->algorithmManagerFactory->add('ECDH-ES+A256KW', new KeyEncryption\ECDHESA256KW());
            $this->algorithmManagerFactory->add('PBES2-HS256+A128KW', new KeyEncryption\PBES2HS256A128KW());
            $this->algorithmManagerFactory->add('PBES2-HS384+A192KW', new KeyEncryption\PBES2HS384A192KW());
            $this->algorithmManagerFactory->add('PBES2-HS512+A256KW', new KeyEncryption\PBES2HS512A256KW());
            $this->algorithmManagerFactory->add('RSA1_5', new KeyEncryption\RSA15());
            $this->algorithmManagerFactory->add('RSA-OAEP', new KeyEncryption\RSAOAEP());
            $this->algorithmManagerFactory->add('RSA-OAEP-256', new KeyEncryption\RSAOAEP256());
        }

        return $this->algorithmManagerFactory;
    }

    protected function getCompressionMethodManagerFactory(): CompressionMethodManagerFactory
    {
        if (null === $this->compressionMethodManagerFactory) {
            $this->compressionMethodManagerFactory = new CompressionMethodManagerFactory();
            $this->compressionMethodManagerFactory->add('DEF', new Compression\Deflate());
        }

        return $this->compressionMethodManagerFactory;
    }

    protected function getJWEBuilderFactory(): JWEBuilderFactory
    {
        if (null === $this->jweBuilderFactory) {
            $this->jweBuilderFactory = new JWEBuilderFactory(
                $this->getAlgorithmManagerFactory(),
                $this->getCompressionMethodManagerFactory()
            );
        }

        return $this->jweBuilderFactory;
    }

    protected function getJWEDecrypterFactory(): JWEDecrypterFactory
    {
        if (null === $this->jweDecrypterFactory) {
            $this->jweDecrypterFactory = new JWEDecrypterFactory(
                $this->getAlgorithmManagerFactory(),
                $this->getCompressionMethodManagerFactory()
            );
        }

        return $this->jweDecrypterFactory;
    }

    protected function getJWELoaderFactory(): JWELoaderFactory
    {
        if (null === $this->jweLoaderFactory) {
            $this->jweLoaderFactory = new JWELoaderFactory(
                $this->getJWESerializerManagerFactory(),
                $this->getJWEDecrypterFactory(),
                null
            );
        }

        return $this->jweLoaderFactory;
    }

    protected function getJWESerializerManagerFactory(): Serializer\JWESerializerManagerFactory
    {
        if (null === $this->jwsSerializerManagerFactory) {
            $this->jwsSerializerManagerFactory = new Serializer\JWESerializerManagerFactory();
            $this->jwsSerializerManagerFactory->add(new Serializer\CompactSerializer());
            $this->jwsSerializerManagerFactory->add(new Serializer\JSONFlattenedSerializer());
            $this->jwsSerializerManagerFactory->add(new Serializer\JSONGeneralSerializer());
        }

        return $this->jwsSerializerManagerFactory;
    }

    protected function getJWESerializerManager(): Serializer\JWESerializerManager
    {
        if (null === $this->jwsSerializerManager) {
            $this->jwsSerializerManager = new Serializer\JWESerializerManager([
                new Serializer\CompactSerializer(),
                new Serializer\JSONFlattenedSerializer(),
                new Serializer\JSONGeneralSerializer(),
            ]);
        }

        return $this->jwsSerializerManager;
    }
}

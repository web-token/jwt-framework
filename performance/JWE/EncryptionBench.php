<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWE;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Compression;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;

/**
 * @BeforeMethods({"init"})
 * @Groups({"JWE"})
 * @Revs(100)
 */
abstract class EncryptionBench
{
    /**
     * @param JWAManager
     */
    private $contentEncryptionAlgorithmsManager;

    /**
     * @param JWAManager
     */
    private $keyEncryptionAlgorithmsManager;

    /**
     * @param CompressionManager
     */
    private $compressionMethodsManager;

    /**
     * @var JsonConverter
     */
    private $jsonConverter;

    /**
     * @var HeaderCheckerManager
     */
    private $headerCherckerManager;

    /**
     * @var JWESerializerManager
     */
    private $serializerManager;

    public function init()
    {
        $this->jsonConverter = new StandardConverter();
        $this->keyEncryptionAlgorithmsManager = AlgorithmManager::create([
            new KeyEncryption\A128KW(),
            new KeyEncryption\A192KW(),
            new KeyEncryption\A256KW(),
            new KeyEncryption\A128GCMKW(),
            new KeyEncryption\A192GCMKW(),
            new KeyEncryption\A256GCMKW(),
            new KeyEncryption\Dir(),
            new KeyEncryption\ECDHES(),
            new KeyEncryption\ECDHESA128KW(),
            new KeyEncryption\ECDHESA192KW(),
            new KeyEncryption\ECDHESA256KW(),
            new KeyEncryption\PBES2HS256A128KW(),
            new KeyEncryption\PBES2HS384A192KW(),
            new KeyEncryption\PBES2HS512A256KW(),
            new KeyEncryption\RSA15(),
            new KeyEncryption\RSAOAEP(),
            new KeyEncryption\RSAOAEP256(),
        ]);
        $this->contentEncryptionAlgorithmsManager = AlgorithmManager::create([
            new ContentEncryption\A128CBCHS256(),
            new ContentEncryption\A192CBCHS384(),
            new ContentEncryption\A256CBCHS512(),
            new ContentEncryption\A128GCM(),
            new ContentEncryption\A192GCM(),
            new ContentEncryption\A256GCM(),
        ]);
        $this->compressionMethodsManager = CompressionMethodManager::create([
            new Compression\Deflate(),
            new Compression\GZip(),
            new Compression\ZLib(),
        ]);
        $this->headerCherckerManager = HeaderCheckerManager::create([
        ], [
            new JWETokenSupport(),
        ]);
        $this->serializerManager = JWESerializerManager::create([
            new CompactSerializer($this->jsonConverter),
            new JSONFlattenedSerializer($this->jsonConverter),
            new JSONGeneralSerializer($this->jsonConverter),
        ]);
    }

    /**
     * @param array $params
     *
     * @Subject()
     * @ParamProviders({"dataPayloads", "dataHeadersAndAlgorithms", "dataRecipientPublicKeys"})
     */
    public function encryption(array $params)
    {
        $jweBuilder = new JWEBuilder(
            $this->jsonConverter,
            $this->getKeyEncryptionAlgorithmsManager(),
            $this->getContentEncryptionAlgorithmsManager(),
            $this->getCompressionMethodsManager()
        );
        $jweBuilder
            ->withPayload($params['payload'])
            ->withAAD($this->getAAD())
            ->withSharedProtectedHeaders($params['shared_protected_headers'])
            ->withSharedHeaders($params['shared_headers'])
            ->addRecipient(JWK::create($params['recipient_key']), $params['recipient_headers'])
            ->build();
    }

    /**
     * @param array $params
     *
     * @Subject()
     * @ParamProviders({"dataInputs", "dataPrivateKeys"})
     */
    public function decryption(array $params)
    {
        $jweLoader = new JWEDecrypter(
            $this->getKeyEncryptionAlgorithmsManager(),
            $this->getContentEncryptionAlgorithmsManager(),
            $this->getCompressionMethodsManager(),
            $this->headerCherckerManager
        );
        $jwe = $this->serializerManager->unserialize($params['input']);
        $keyset = JWKSet::createFromKeyData($params['recipient_keys']);
        $jweLoader->decryptUsingKeySet($jwe, $keyset);
    }

    /**
     * @return array
     */
    public function dataPayloads(): array
    {
        return [
            [
                'payload' => "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.",
            ],
        ];
    }

    /**
     * @return array
     */
    abstract public function dataHeadersAndAlgorithms(): array;

    /**
     * @return array
     */
    abstract public function dataRecipientPublicKeys(): array;

    /**
     * @return null|string
     */
    abstract protected function getAAD(): ?string;

    /**
     * @return AlgorithmManager
     */
    private function getKeyEncryptionAlgorithmsManager(): AlgorithmManager
    {
        return $this->keyEncryptionAlgorithmsManager;
    }

    /**
     * @return AlgorithmManager
     */
    private function getContentEncryptionAlgorithmsManager(): AlgorithmManager
    {
        return $this->contentEncryptionAlgorithmsManager;
    }

    /**
     * @return CompressionMethodManager
     */
    private function getCompressionMethodsManager(): CompressionMethodManager
    {
        return $this->compressionMethodsManager;
    }
}

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

namespace Jose\Performance\JWE;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Jose\Component\Encryption\Compression;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
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
    private $contentEncryptionAlgorithmsManager;
    private $keyEncryptionAlgorithmsManager;
    private $compressionMethodsManager;
    private $jsonConverter;
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
        $this->serializerManager = JWESerializerManager::create([
            new CompactSerializer($this->jsonConverter),
            new JSONFlattenedSerializer($this->jsonConverter),
            new JSONGeneralSerializer($this->jsonConverter),
        ]);
    }

    /**
     * @Subject
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
            ->withSharedProtectedHeader($params['shared_protected_header'])
            ->withSharedHeader($params['shared_header'])
            ->addRecipient(new JWK($params['recipient_key']), $params['recipient_header'])
            ->build();
    }

    /**
     * @Subject
     * @ParamProviders({"dataInputs", "dataPrivateKeys"})
     */
    public function decryption(array $params)
    {
        $jweLoader = new JWEDecrypter(
            $this->getKeyEncryptionAlgorithmsManager(),
            $this->getContentEncryptionAlgorithmsManager(),
            $this->getCompressionMethodsManager()
        );
        $jwe = $this->serializerManager->unserialize($params['input']);
        $keyset = JWKSet::createFromKeyData($params['recipient_keys']);
        $jweLoader->decryptUsingKeySet($jwe, $keyset, 0);
    }

    public function dataPayloads(): array
    {
        return [
            [
                'payload' => "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.",
            ],
        ];
    }

    abstract public function dataHeadersAndAlgorithms(): array;

    abstract public function dataRecipientPublicKeys(): array;

    abstract protected function getAAD(): ?string;

    private function getKeyEncryptionAlgorithmsManager(): AlgorithmManager
    {
        return $this->keyEncryptionAlgorithmsManager;
    }

    private function getContentEncryptionAlgorithmsManager(): AlgorithmManager
    {
        return $this->contentEncryptionAlgorithmsManager;
    }

    private function getCompressionMethodsManager(): CompressionMethodManager
    {
        return $this->compressionMethodsManager;
    }
}

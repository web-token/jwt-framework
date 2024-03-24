<?php

declare(strict_types=1);

namespace Jose\Performance\JWE;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
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
    private AlgorithmManager $algorithmsManager;

    private JWESerializerManager $serializerManager;

    public function init(): void
    {
        $this->algorithmsManager = new AlgorithmManager([
            // Key Encryption
            new A128KW(),
            new A192KW(),
            new A256KW(),
            new A128GCMKW(),
            new A192GCMKW(),
            new A256GCMKW(),
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

            // Content Encryption
            new A128CBCHS256(),
            new A192CBCHS384(),
            new A256CBCHS512(),
            new A128GCM(),
            new A192GCM(),
            new A256GCM(),
        ]);
        $this->serializerManager = new JWESerializerManager([
            new CompactSerializer(),
            new JSONFlattenedSerializer(),
            new JSONGeneralSerializer(),
        ]);
    }

    /**
     * @Subject
     * @ParamProviders({"dataPayloads", "dataHeadersAndAlgorithms", "dataRecipientPublicKeys"})
     */
    public function encryption(array $params): void
    {
        $jweBuilder = new JWEBuilder($this->getAlgorithmsManager());
        $jweBuilder
            ->withPayload($params['payload'])
            ->withAAD($this->getAAD())
            ->withSharedProtectedHeader($params['shared_protected_header'])
            ->withSharedHeader($params['shared_header'])
            ->addRecipient(new JWK($params['recipient_key']), $params['recipient_header'])
            ->build()
        ;
    }

    /**
     * @Subject
     * @ParamProviders({"dataInputs", "dataPrivateKeys"})
     */
    public function decryption(array $params): void
    {
        $jweLoader = new JWEDecrypter($this->getAlgorithmsManager());
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

    private function getAlgorithmsManager(): AlgorithmManager
    {
        return $this->algorithmsManager;
    }
}

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Easy;

use InvalidArgumentException;
use Jose\Component\Checker;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Jose\Component\Encryption\Compression\CompressionMethod;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\CompactSerializer;

class Decrypt extends AbstractLoader
{
    /**
     * @var string[]
     */
    protected $allowedContentEncryptionAlgorithms = [];
    /**
     * @var CompressionMethod[]
     */
    private $compressionMethods;

    private function __construct(string $token)
    {
        parent::__construct($token);
        $this->algorithms = [
            new KeyEncryption\A128GCMKW(),
            new KeyEncryption\A192GCMKW(),
            new KeyEncryption\A256GCMKW(),
            new KeyEncryption\A128KW(),
            new KeyEncryption\A192KW(),
            new KeyEncryption\A256KW(),
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
            new ContentEncryption\A128GCM(),
            new ContentEncryption\A192GCM(),
            new ContentEncryption\A256GCM(),
            new ContentEncryption\A128CBCHS256(),
            new ContentEncryption\A192CBCHS384(),
            new ContentEncryption\A256CBCHS512(),
        ];
        $this->compressionMethods = [
            new Deflate(),
        ];
    }

    public static function token(string $token): self
    {
        return new self($token);
    }

    /**
     * @param Algorithm|string $enc
     *
     * @throws InvalidArgumentException if the encryption algorithm is invalid
     */
    public function enc($enc): self
    {
        $clone = clone $this;
        switch (true) {
            case \is_string($enc):
                $clone->allowedContentEncryptionAlgorithms[] = $enc;

                return $clone;
            case $enc instanceof Algorithm:
                $clone->algorithms[$enc->name()] = $enc;
                $clone->allowedContentEncryptionAlgorithms[] = $enc->name();

                return $clone;
            default:
                throw new InvalidArgumentException('Invalid parameter "enc". Shall be a string or an algorithm instance.');
        }
    }

    /**
     * @param Algorithm[]|string[] $encs
     */
    public function encs($encs): self
    {
        $clone = clone $this;
        foreach ($encs as $enc) {
            $clone = $clone->enc($enc);
        }

        return $clone;
    }

    public function run(): JWT
    {
        if (0 !== \count($this->allowedAlgorithms)) {
            $this->headerCheckers[] = new Checker\AlgorithmChecker($this->allowedAlgorithms, true);
        }
        if (0 !== \count($this->allowedContentEncryptionAlgorithms)) {
            $this->headerCheckers[] = new ContentEncryptionAlgorithmChecker($this->allowedContentEncryptionAlgorithms, true);
        }
        $jwe = (new CompactSerializer())->unserialize($this->token);
        $headerChecker = new Checker\HeaderCheckerManager($this->headerCheckers, [new JWETokenSupport()]);
        $headerChecker->check($jwe, 0);

        $verifier = new JWEDecrypter(
            new AlgorithmManager($this->algorithms),
            new AlgorithmManager($this->algorithms),
            new CompressionMethodManager($this->compressionMethods)
        );
        $verifier->decryptUsingKeySet($jwe, $this->jwkset, 0);

        $jwt = new JWT();
        $jwt->header->replace($jwe->getSharedProtectedHeader());
        $jwt->claims->replace(JsonConverter::decode($jwe->getPayload()));

        $claimChecker = new Checker\ClaimCheckerManager($this->claimCheckers);
        $claimChecker->check($jwt->claims->all());

        return $jwt;
    }
}

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
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Jose\Component\Encryption\Compression\CompressionMethod;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder as JoseBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;

class JWEBuilder
{
    private $jwt;

    /**
     * @var CompactSerializer
     */
    private $serializer;

    /**
     * @var JoseBuilder
     */
    private $builder;

    /**
     * @var AlgorithmManager
     */
    private $keyEncryptionAlgorithms;

    /**
     * @var AlgorithmManager
     */
    private $contentEncryptionAlgorithms;

    /**
     * @var CompressionMethodManager
     */
    private $compressionMethods;

    /**
     * @var Algorithm|string
     */
    private $keyEncryptionAlgorithm;

    /**
     * @var Algorithm|string
     */
    private $contentEncryptionAlgorithm;

    /**
     * @var CompressionMethod
     */
    private $compressionMethod;

    public function __construct()
    {
        $this->jwt = new JWT();
        $this->serializer = new CompactSerializer();
        $this->keyEncryptionAlgorithms = new AlgorithmManager([
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
        ]);
        $this->contentEncryptionAlgorithms = new AlgorithmManager([
            new ContentEncryption\A128GCM(),
            new ContentEncryption\A192GCM(),
            new ContentEncryption\A256GCM(),
            new ContentEncryption\A128CBCHS256(),
            new ContentEncryption\A192CBCHS384(),
            new ContentEncryption\A256CBCHS512(),
        ]);
        $this->compressionMethods = new CompressionMethodManager([
            new Deflate(),
        ]);
    }

    public function payload(array $payload): self
    {
        $clone = clone $this;
        $clone->jwt->payload->replace($payload);

        return $clone;
    }

    public function iss(string $iss, bool $inHeader = false): self
    {
        return $this->claim('iss', $iss, $inHeader);
    }

    public function sub(string $sub, bool $inHeader = false): self
    {
        return $this->claim('sub', $sub, $inHeader);
    }

    public function aud(string $aud, bool $inHeader = false): self
    {
        $audience = $this->jwt->payload->get('aud', []);
        $audience[] = $aud;

        return $this->claim('aud', $audience, $inHeader);
    }

    public function jti(string $jti, bool $inHeader = false): self
    {
        return $this->claim('jti', $jti, $inHeader);
    }

    public function exp(int $exp, bool $inHeader = false): self
    {
        return $this->claim('exp', $exp, $inHeader);
    }

    public function iat(int $iat, bool $inHeader = false): self
    {
        return $this->claim('iat', $iat, $inHeader);
    }

    public function nbf(int $nbf, bool $inHeader = false): self
    {
        return $this->claim('nbf', $nbf, $inHeader);
    }

    /**
     * @param Algorithm|string $alg
     */
    public function alg($alg): self
    {
        if ($alg instanceof Algorithm) {
            $clone = clone $this;
            $clone->keyEncryptionAlgorithm = $alg;
            $clone->jwt->header->set('alg', $alg->name());

            return $clone;
        }
        if (!\is_string($alg)) {
            throw new InvalidArgumentException('Invalid key encryption algorithm');
        }
        $clone = clone $this;
        $clone->keyEncryptionAlgorithm = null;

        return $clone->header('alg', $alg);
    }

    /**
     * @param Algorithm|string $alg
     * @param mixed            $enc
     */
    public function enc($enc): self
    {
        if ($enc instanceof Algorithm) {
            $clone = clone $this;
            $clone->contentEncryptionAlgorithm = $enc;
            $clone->jwt->header->set('enc', $enc->name());

            return $clone;
        }
        if (!\is_string($enc)) {
            throw new InvalidArgumentException('Invalid content encryption algorithm');
        }
        $clone = clone $this;
        $clone->contentEncryptionAlgorithm = null;

        return $this->header('enc', $enc);
    }

    /**
     * @param CompressionMethod|string $alg
     * @param mixed                    $zip
     */
    public function zip($zip): self
    {
        if ($zip instanceof CompressionMethod) {
            $clone = clone $this;
            $clone->compressionMethod = $zip;
            $clone->jwt->header->set('zip', $zip->name());

            return $clone;
        }
        if (!\is_string($zip)) {
            throw new InvalidArgumentException('Invalid compression method');
        }
        $clone = clone $this;
        $clone->compressionMethod = null;

        return $this->header('zip', $zip);
    }

    public function cty(string $cty): self
    {
        return $this->header('cty', $cty);
    }

    public function typ(string $typ): self
    {
        return $this->header('typ', $typ);
    }

    /**
     * @param mixed $value
     */
    public function claim(string $key, $value, bool $inHeader = false): self
    {
        $clone = clone $this;
        $clone->jwt->payload->set($key, $value);
        if ($inHeader) {
            $clone->jwt->header->set($key, $value);
        }

        return $clone;
    }

    /**
     * @param mixed $value
     */
    public function header(string $key, $value): self
    {
        $clone = clone $this;
        $clone->jwt->header->set($key, $value);

        return $clone;
    }

    public function encrypt(JWK $jwk): string
    {
        $keyEncryptionAlgorithms = $this->keyEncryptionAlgorithms;
        if (null !== $this->keyEncryptionAlgorithm) {
            $keyEncryptionAlgorithms = new AlgorithmManager([$this->keyEncryptionAlgorithm]);
        }
        $contentEncryptionAlgorithms = $this->contentEncryptionAlgorithms;
        if (null !== $this->contentEncryptionAlgorithm) {
            $contentEncryptionAlgorithms = new AlgorithmManager([$this->contentEncryptionAlgorithm]);
        }
        $compressionMethods = $this->compressionMethods;
        if (null !== $this->compressionMethod) {
            $compressionMethods = new AlgorithmManager([$this->compressionMethod]);
        }

        $builder = new JoseBuilder(
            $keyEncryptionAlgorithms,
            $contentEncryptionAlgorithms,
            $compressionMethods
        );
        $jws = $builder
            ->create()
            ->withPayload(JsonConverter::encode($this->jwt->payload->all()))
            ->withSharedProtectedHeader($this->jwt->header->all())
            ->addRecipient($jwk)
            ->build()
        ;

        return $this->serializer->serialize($jws);
    }
}

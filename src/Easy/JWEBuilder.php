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

class JWEBuilder extends AbstractBuilder
{
    /**
     * @var CompressionMethod[]
     */
    private $compressionMethods;

    public function __construct()
    {
        parent::__construct();
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

    /**
     * @param Algorithm|string $alg
     * @param mixed            $enc
     */
    public function enc($enc): self
    {
        $clone = clone $this;
        switch (true) {
            case $enc instanceof Algorithm:
                $clone->algorithms[] = $enc;
                $clone->jwt->header->set('enc', $enc->name());

                break;
            case \is_string($enc):
                $clone->jwt->header->set('enc', $enc);

                break;
            default:
                throw new InvalidArgumentException('Invalid algorithm');
        }

        return $clone;
    }

    /**
     * @param CompressionMethod|string $alg
     * @param mixed                    $zip
     */
    public function zip($zip): self
    {
        $clone = clone $this;
        switch (true) {
            case $zip instanceof CompressionMethod:
                $clone->compressionMethods[] = $zip;
                $clone->jwt->header->set('zip', $zip->name());

                break;
            case \is_string($zip):
                $clone->jwt->header->set('zip', $zip);

                break;
            default:
                throw new InvalidArgumentException('Invalid compression method');
        }

        return $clone;
    }

    public function encrypt(JWK $jwk): string
    {
        $builder = new JoseBuilder(
            new AlgorithmManager($this->algorithms),
            new AlgorithmManager($this->algorithms),
            new CompressionMethodManager($this->compressionMethods)
        );
        $jwe = $builder
            ->create()
            ->withPayload(JsonConverter::encode($this->jwt->claims->all()))
            ->withSharedProtectedHeader($this->jwt->header->all())
            ->addRecipient($jwk)
            ->build()
        ;

        return (new CompactSerializer())->serialize($jwe);
    }
}

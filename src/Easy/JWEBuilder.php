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

namespace Jose\Easy;

use InvalidArgumentException;
use function is_string;
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
        $this->compressionMethods = [
            new Deflate(),
        ];
    }

    /**
     * @param Algorithm|string $enc
     *
     * @throws InvalidArgumentException if the header parameter "enc" is invalid
     */
    public function enc($enc): self
    {
        $clone = clone $this;
        switch (true) {
            case $enc instanceof Algorithm:
                $clone->algorithms[] = $enc;
                $clone->jwt->header->set('enc', $enc->name());

                break;
            case is_string($enc):
                $clone->jwt->header->set('enc', $enc);

                break;
            default:
                throw new InvalidArgumentException('Invalid algorithm');
        }

        return $clone;
    }

    /**
     * @param CompressionMethod|string $zip
     *
     * @throws InvalidArgumentException if the header parameter "zip" is invalid
     */
    public function zip($zip): self
    {
        $clone = clone $this;
        switch (true) {
            case $zip instanceof CompressionMethod:
                $clone->compressionMethods[] = $zip;
                $clone->jwt->header->set('zip', $zip->name());

                break;
            case is_string($zip):
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

    protected function getAlgorithmMap(): array
    {
        return [
            KeyEncryption\A128GCMKW::class,
            KeyEncryption\A192GCMKW::class,
            KeyEncryption\A256GCMKW::class,
            KeyEncryption\A128KW::class,
            KeyEncryption\A192KW::class,
            KeyEncryption\A256KW::class,
            KeyEncryption\Dir::class,
            KeyEncryption\ECDHES::class,
            KeyEncryption\ECDHESA128KW::class,
            KeyEncryption\ECDHESA192KW::class,
            KeyEncryption\ECDHESA256KW::class,
            KeyEncryption\PBES2HS256A128KW::class,
            KeyEncryption\PBES2HS384A192KW::class,
            KeyEncryption\PBES2HS512A256KW::class,
            KeyEncryption\RSA15::class,
            KeyEncryption\RSAOAEP::class,
            KeyEncryption\RSAOAEP256::class,
            ContentEncryption\A128GCM::class,
            ContentEncryption\A192GCM::class,
            ContentEncryption\A256GCM::class,
            ContentEncryption\A128CBCHS256::class,
            ContentEncryption\A192CBCHS384::class,
            ContentEncryption\A256CBCHS512::class,
        ];
    }
}

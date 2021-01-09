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

namespace Jose\Tests\Component\Signature\Algorithm;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256K;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @group NewAlgorithm
 *
 * @covers \Jose\Component\Signature\Algorithm\ES256K
 *
 * @internal
 */
class P256KSignatureTest extends TestCase
{
    /**
     * @test
     */
    public function es256KVerify(): void
    {
        $key = $this->getKey();
        $algorithm = new ES256K();
        $data = 'Hello';

        static::assertTrue($algorithm->verify($key, $data, hex2bin('9c75b9d171d9690a37f2474d4bfab5c234911cb150950ea5cbfc9aedda5ec360725cc47978de95b4efb2a3ed617c7b36b1cd0a26b536662a79d0f3ae873a7924')));
    }

    /**
     * @test
     */
    public function es256KSignAndVerify(): void
    {
        $key = $this->getKey();
        $algorithm = new ES256K();
        $data = 'Hello';

        static::assertEquals('ES256K', $algorithm->name());

        $signature = $algorithm->sign($key, $data);

        static::assertTrue($algorithm->verify($key, $data, $signature));
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'secp256k1',
            'd' => Base64Url::encode(hex2bin('D1592A94BBB9B5D94CDC425FC7DA80B6A47863AE973A9D581FD9D8F29690B659')),
            'x' => Base64Url::encode(hex2bin('4B4DF318DE05BB8F3A115BF337F9BCBC55CA14B917B46BCB557D3C9A158D4BE0')),
            'y' => Base64Url::encode(hex2bin('627EB75731A8BBEBC7D9A3C57EC4D7DA2CBA6D2A28E7F45134921861FE1CF5D9')),
        ]);
    }
}

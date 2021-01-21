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

namespace Jose\Tests\Component\Encryption\Algorithm\KeyEncryption;

use function array_key_exists;
use Base64Url\Base64Url;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use PHPUnit\Framework\TestCase;

/**
 * Class ECDHESKeyAgreementTest.
 *
 * @group ECDHES
 * @group unit
 *
 * @internal
 */
class ECDHESKeyAgreementTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7518#appendix-C
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES
     *
     * @test
     */
    public function getAgreementKey(): void
    {
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];
        $ecdh_es = new ECDHES();
        $additional_header_values = [];

        $ecdh_es->getAgreementKey(128, 'A128GCM', $receiver, null, $header, $additional_header_values);
        static::assertTrue(array_key_exists('epk', $additional_header_values));
        static::assertTrue(array_key_exists('kty', $additional_header_values['epk']));
        static::assertTrue(array_key_exists('crv', $additional_header_values['epk']));
        static::assertTrue(array_key_exists('x', $additional_header_values['epk']));
        static::assertTrue(array_key_exists('y', $additional_header_values['epk']));
    }

    /**
     * @test
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW
     */
    public function getAgreementKeyWithA128KeyWrap(): void
    {
        $header = ['enc' => 'A128GCM'];

        $private = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
        $public = $private->toPublic();

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA128KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, null, $cek, 128, $header, $header);
        static::assertTrue(array_key_exists('epk', $header));
        static::assertTrue(array_key_exists('crv', $header['epk']));
        static::assertTrue(array_key_exists('kty', $header['epk']));
        static::assertTrue(array_key_exists('x', $header['epk']));
        static::assertTrue(array_key_exists('y', $header['epk']));
        static::assertEquals('P-256', $header['epk']['crv']);
        static::assertEquals('EC', $header['epk']['kty']);
        static::assertEquals($cek, $ecdh_es->unwrapAgreementKey($private, null, $encrypted_cek, 128, $header));
    }

    /**
     * @test
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW
     */
    public function getAgreementKeyWithA192KeyWrap(): void
    {
        $header = ['enc' => 'A192GCM'];

        $private = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
        $public = $private->toPublic();

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA192KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, null, $cek, 192, $header, $header);
        static::assertTrue(array_key_exists('epk', $header));
        static::assertTrue(array_key_exists('crv', $header['epk']));
        static::assertTrue(array_key_exists('kty', $header['epk']));
        static::assertTrue(array_key_exists('x', $header['epk']));
        static::assertTrue(array_key_exists('y', $header['epk']));
        static::assertEquals('P-256', $header['epk']['crv']);
        static::assertEquals('EC', $header['epk']['kty']);
        static::assertEquals($cek, $ecdh_es->unwrapAgreementKey($private, null, $encrypted_cek, 192, $header));
    }

    /**
     * @test
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW
     */
    public function getAgreementKeyWithA256KeyWrap(): void
    {
        $header = ['enc' => 'A256GCM'];

        $public = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $private = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA256KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, null, $cek, 256, $header, $header);
        static::assertTrue(array_key_exists('epk', $header));
        static::assertTrue(array_key_exists('crv', $header['epk']));
        static::assertTrue(array_key_exists('kty', $header['epk']));
        static::assertTrue(array_key_exists('x', $header['epk']));
        static::assertTrue(array_key_exists('y', $header['epk']));
        static::assertEquals('P-256', $header['epk']['crv']);
        static::assertEquals('EC', $header['epk']['kty']);
        static::assertEquals($cek, $ecdh_es->unwrapAgreementKey($private, null, $encrypted_cek, 256, $header));
    }

    /**
     * @test
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES
     */
    public function ePKParameterAreMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header parameter "epk" is missing');

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $sender, null);
    }

    /**
     * @test
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES
     */
    public function badEPKParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header parameter "epk" is not an array of parameters');

        $header = ['epk' => 'foo'];
        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $sender, null, $header);
    }

    /**
     * @test
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES
     */
    public function eCKeyHasMissingParameters(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key parameter "x" is missing.');

        $receiver = new JWK([
            'kty' => 'EC',
            'dir' => Base64Url::encode('ABCD'),
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $receiver, null);
    }

    /**
     * @test
     * @covers \Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES
     */
    public function unsupportedCurve(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The curve "P-192" is not supported');

        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];

        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-192',
            'x' => 'm2Jmp98NRH83ramvp0VVIQJXK56ZEwuM',
            'y' => '84lz6hQtPJe9WFPPgEyOUwh3tuW2kOS_',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $receiver, null, $header);
    }
}

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

namespace Jose\Component\Encryption\Tests;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;

/**
 * Class ECDHESKeyAgreementTest.
 *
 * @group ECDHES
 * @group Unit
 */
final class ECDHESKeyAgreementTest extends EncryptionTest
{
    /**
     * @see https://tools.ietf.org/html/rfc7518#appendix-C
     */
    public function testGetAgreementKey()
    {
        $receiver = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];
        $ecdh_es = new ECDHES();
        $additional_header_values = [];

        $ecdh_es->getAgreementKey(128, 'A128GCM', $receiver, $header, $additional_header_values);
        self::assertTrue(array_key_exists('epk', $additional_header_values));
        self::assertTrue(array_key_exists('kty', $additional_header_values['epk']));
        self::assertTrue(array_key_exists('crv', $additional_header_values['epk']));
        self::assertTrue(array_key_exists('x', $additional_header_values['epk']));
        self::assertTrue(array_key_exists('y', $additional_header_values['epk']));
    }

    public function testGetAgreementKeyWithA128KeyWrap()
    {
        $header = ['enc' => 'A128GCM'];

        $public = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $private = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA128KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, $cek, 128, $header, $header);
        self::assertTrue(array_key_exists('epk', $header));
        self::assertTrue(array_key_exists('crv', $header['epk']));
        self::assertTrue(array_key_exists('kty', $header['epk']));
        self::assertTrue(array_key_exists('x', $header['epk']));
        self::assertTrue(array_key_exists('y', $header['epk']));
        self::assertEquals('P-256', $header['epk']['crv']);
        self::assertEquals('EC', $header['epk']['kty']);
        self::assertEquals($cek, $ecdh_es->unwrapAgreementKey($private, $encrypted_cek, 128, $header));
    }

    public function testGetAgreementKeyWithA192KeyWrap()
    {
        $header = ['enc' => 'A192GCM'];

        $public = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $private = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA192KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, $cek, 192, $header, $header);
        self::assertTrue(array_key_exists('epk', $header));
        self::assertTrue(array_key_exists('crv', $header['epk']));
        self::assertTrue(array_key_exists('kty', $header['epk']));
        self::assertTrue(array_key_exists('x', $header['epk']));
        self::assertTrue(array_key_exists('y', $header['epk']));
        self::assertEquals('P-256', $header['epk']['crv']);
        self::assertEquals('EC', $header['epk']['kty']);
        self::assertEquals($cek, $ecdh_es->unwrapAgreementKey($private, $encrypted_cek, 192, $header));
    }

    public function testGetAgreementKeyWithA256KeyWrap()
    {
        $header = ['enc' => 'A256GCM'];

        $public = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);

        $private = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);

        $cek = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($cek as $key => $value) {
            $cek[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA256KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, $cek, 256, $header, $header);
        self::assertTrue(array_key_exists('epk', $header));
        self::assertTrue(array_key_exists('crv', $header['epk']));
        self::assertTrue(array_key_exists('kty', $header['epk']));
        self::assertTrue(array_key_exists('x', $header['epk']));
        self::assertTrue(array_key_exists('y', $header['epk']));
        self::assertEquals('P-256', $header['epk']['crv']);
        self::assertEquals('EC', $header['epk']['kty']);
        self::assertEquals($cek, $ecdh_es->unwrapAgreementKey($private, $encrypted_cek, 256, $header));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header parameter "epk" is missing
     */
    public function testEPKParameterAreMissing()
    {
        $sender = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $sender);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header parameter "epk" is not an array of parameter
     */
    public function testBadEPKParameter()
    {
        $header = ['epk' => 'foo'];
        $sender = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
            'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
            'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $sender, $header);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The key parameter "x" is missing.
     */
    public function testECKeyHasMissingParameters()
    {
        $receiver = JWK::create([
            'kty' => 'EC',
            'dir' => Base64Url::encode('ABCD'),
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $receiver);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The curve "P-192" is not supported
     */
    public function testUnsupportedCurve()
    {
        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];

        $receiver = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-192',
            'x'   => 'm2Jmp98NRH83ramvp0VVIQJXK56ZEwuM',
            'y'   => '84lz6hQtPJe9WFPPgEyOUwh3tuW2kOS_',
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $receiver, $header);
    }
}

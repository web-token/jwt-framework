<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\KeyEncryption\ECDHES;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const STR_PAD_LEFT;

/**
 * Class ECDHESKeyAgreementTest.
 *
 * @internal
 */
final class ECDHESKeyAgreementTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7518#appendix-C
     */
    #[Test]
    public function getAgreementKeyWithEllipticCurveKey(): void
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
        static::assertArrayHasKey('epk', $additional_header_values);
        static::assertArrayHasKey('kty', $additional_header_values['epk']);
        static::assertArrayHasKey('crv', $additional_header_values['epk']);
        static::assertArrayHasKey('x', $additional_header_values['epk']);
        static::assertArrayHasKey('y', $additional_header_values['epk']);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7518#appendix-C
     */
    #[Test]
    public function getAgreementKeyWithA128KeyWrapAndWithOctetKeyPairKey(): void
    {
        $header = [
            'enc' => 'A128GCM',
        ];

        $private = new JWK([
            'kty' => 'OKP',
            'crv' => 'X25519',
            'd' => 'uns2Byv3po_cjjG8XRCtU-lEOrOgLbsDr5cXHmgjVvA',
            'x' => 'k8IkMMO9I0foCYqEcbfM49DjEoWpHdho_GKNMXk1rFw',
        ]);
        $public = $private->toPublic();

        $cek = [
            4,
            211,
            31,
            197,
            84,
            157,
            252,
            254,
            11,
            100,
            157,
            250,
            63,
            170,
            106,
            206,
            107,
            124,
            212,
            45,
            111,
            107,
            9,
            219,
            200,
            177,
            0,
            240,
            143,
            156,
            44,
            207,
        ];
        foreach ($cek as $key => $value) {
            $cek[$key] = mb_str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA128KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, null, $cek, 128, $header, $header);
        static::assertArrayHasKey('epk', $header);
        static::assertArrayHasKey('crv', $header['epk']);
        static::assertArrayHasKey('kty', $header['epk']);
        static::assertArrayHasKey('x', $header['epk']);
        static::assertArrayNotHasKey('y', $header['epk']);
        static::assertSame('X25519', $header['epk']['crv']);
        static::assertSame('OKP', $header['epk']['kty']);
        static::assertSame($cek, $ecdh_es->unwrapAgreementKey($private, null, $encrypted_cek, 128, $header));
    }

    #[Test]
    public function getAgreementKeyWithA128KeyWrap(): void
    {
        $header = [
            'enc' => 'A128GCM',
        ];

        $private = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
        $public = $private->toPublic();

        $cek = [
            4,
            211,
            31,
            197,
            84,
            157,
            252,
            254,
            11,
            100,
            157,
            250,
            63,
            170,
            106,
            206,
            107,
            124,
            212,
            45,
            111,
            107,
            9,
            219,
            200,
            177,
            0,
            240,
            143,
            156,
            44,
            207,
        ];
        foreach ($cek as $key => $value) {
            $cek[$key] = mb_str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA128KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, null, $cek, 128, $header, $header);
        static::assertArrayHasKey('epk', $header);
        static::assertArrayHasKey('crv', $header['epk']);
        static::assertArrayHasKey('kty', $header['epk']);
        static::assertArrayHasKey('x', $header['epk']);
        static::assertArrayHasKey('y', $header['epk']);
        static::assertSame('P-256', $header['epk']['crv']);
        static::assertSame('EC', $header['epk']['kty']);
        static::assertSame($cek, $ecdh_es->unwrapAgreementKey($private, null, $encrypted_cek, 128, $header));
    }

    #[Test]
    public function getAgreementKeyWithA192KeyWrap(): void
    {
        $header = [
            'enc' => 'A192GCM',
        ];

        $private = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
        $public = $private->toPublic();

        $cek = [
            4,
            211,
            31,
            197,
            84,
            157,
            252,
            254,
            11,
            100,
            157,
            250,
            63,
            170,
            106,
            206,
            107,
            124,
            212,
            45,
            111,
            107,
            9,
            219,
            200,
            177,
            0,
            240,
            143,
            156,
            44,
            207,
        ];
        foreach ($cek as $key => $value) {
            $cek[$key] = mb_str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA192KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, null, $cek, 192, $header, $header);
        static::assertArrayHasKey('epk', $header);
        static::assertArrayHasKey('crv', $header['epk']);
        static::assertArrayHasKey('kty', $header['epk']);
        static::assertArrayHasKey('x', $header['epk']);
        static::assertArrayHasKey('y', $header['epk']);
        static::assertSame('P-256', $header['epk']['crv']);
        static::assertSame('EC', $header['epk']['kty']);
        static::assertSame($cek, $ecdh_es->unwrapAgreementKey($private, null, $encrypted_cek, 192, $header));
    }

    #[Test]
    public function getAgreementKeyWithA256KeyWrap(): void
    {
        $header = [
            'enc' => 'A256GCM',
        ];

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

        $cek = [
            4,
            211,
            31,
            197,
            84,
            157,
            252,
            254,
            11,
            100,
            157,
            250,
            63,
            170,
            106,
            206,
            107,
            124,
            212,
            45,
            111,
            107,
            9,
            219,
            200,
            177,
            0,
            240,
            143,
            156,
            44,
            207,
        ];
        foreach ($cek as $key => $value) {
            $cek[$key] = mb_str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $cek = hex2bin(implode('', $cek));

        $ecdh_es = new ECDHESA256KW();
        $encrypted_cek = $ecdh_es->wrapAgreementKey($public, null, $cek, 256, $header, $header);
        static::assertArrayHasKey('epk', $header);
        static::assertArrayHasKey('crv', $header['epk']);
        static::assertArrayHasKey('kty', $header['epk']);
        static::assertArrayHasKey('x', $header['epk']);
        static::assertArrayHasKey('y', $header['epk']);
        static::assertSame('P-256', $header['epk']['crv']);
        static::assertSame('EC', $header['epk']['kty']);
        static::assertSame($cek, $ecdh_es->unwrapAgreementKey($private, null, $encrypted_cek, 256, $header));
    }

    #[Test]
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

    #[Test]
    public function badEPKParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header parameter "epk" is not an array of parameters');

        $header = [
            'epk' => 'foo',
        ];
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

    #[Test]
    public function eCKeyHasMissingParameters(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key parameter "x" is missing.');

        $receiver = new JWK([
            'kty' => 'EC',
            'dir' => Base64UrlSafe::encodeUnpadded('ABCD'),
        ]);

        $ecdh_es = new ECDHES();
        $ecdh_es->getAgreementKey(256, 'A128GCM', $receiver, null);
    }

    #[Test]
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

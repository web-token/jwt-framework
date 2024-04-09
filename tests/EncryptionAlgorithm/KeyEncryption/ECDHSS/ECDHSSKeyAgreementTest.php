<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\KeyEncryption\ECDHSS;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSS;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA256KW;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const STR_PAD_LEFT;

/**
 * Class ECDHSSKeyAgreementTest.
 *
 * @internal
 */
final class ECDHSSKeyAgreementTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7518#appendix-C
     */
    #[Test]
    public function getAgreementKey(): void
    {
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        ]);
        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
            'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
            'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
        ]);

        $header = [
            'enc' => 'A128GCM',
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
        ];
        $ecdh_ss = new ECDHSS();
        $additional_header_values = [];

        $ecdh_ss->getAgreementKey(128, 'A128GCM', $receiver, $sender, $header, $additional_header_values);
        static::assertArrayNotHasKey('epk', $additional_header_values);
    }

    #[Test]
    public function getAgreementKeyWithA128KeyWrapAndOctetKeyPairKey(): void
    {
        $additional_header_values = [
            'enc' => 'A128GCM',
        ];
        $sender = new JWK([
            'kty' => 'OKP',
            'crv' => 'X25519',
            'd' => 'uns2Byv3po_cjjG8XRCtU-lEOrOgLbsDr5cXHmgjVvA',
            'x' => 'k8IkMMO9I0foCYqEcbfM49DjEoWpHdho_GKNMXk1rFw',
        ]);
        $receiver = new JWK([
            'kty' => 'EC',
            'crv' => 'X25519',
            'd' => 'tzF6dJQtUYj2G60lzzw70A8BGeE_KDDofUdwwm9qIEU',
            'x' => 'q9mRLLKfK-_SosZoBFs5LaDxSB9KaqbRaenvzy1_lAA',
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

        $ecdh_ss = new ECDHSSA128KW();
        $encrypted_cek = $ecdh_ss->wrapAgreementKey(
            $receiver->toPublic(),
            $sender,
            $cek,
            128,
            $additional_header_values,
            $additional_header_values
        );
        static::assertArrayNotHasKey('epk', $additional_header_values);
        static::assertSame(
            $cek,
            $ecdh_ss->unwrapAgreementKey($sender->toPublic(), $receiver, $encrypted_cek, 128, $additional_header_values)
        );
    }

    #[Test]
    public function getAgreementKeyWithA128KeyWrap(): void
    {
        $additional_header_values = [
            'enc' => 'A128GCM',
        ];
        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
            'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
            'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
        ]);
        $receiver = new JWK([
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

        $ecdh_ss = new ECDHSSA128KW();
        $encrypted_cek = $ecdh_ss->wrapAgreementKey(
            $receiver->toPublic(),
            $sender,
            $cek,
            128,
            $additional_header_values,
            $additional_header_values
        );
        static::assertArrayNotHasKey('epk', $additional_header_values);
        static::assertSame(
            $cek,
            $ecdh_ss->unwrapAgreementKey($sender->toPublic(), $receiver, $encrypted_cek, 128, $additional_header_values)
        );
    }

    #[Test]
    public function getAgreementKeyWithA192KeyWrap(): void
    {
        $additional_header_values = [
            'enc' => 'A192GCM',
        ];

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
            'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
            'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
        ]);
        $receiver = new JWK([
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

        $ecdh_ss = new ECDHSSA192KW();
        $encrypted_cek = $ecdh_ss->wrapAgreementKey(
            $receiver->toPublic(),
            $sender,
            $cek,
            128,
            $additional_header_values,
            $additional_header_values
        );
        static::assertArrayNotHasKey('epk', $additional_header_values);
        static::assertSame(
            $cek,
            $ecdh_ss->unwrapAgreementKey($sender->toPublic(), $receiver, $encrypted_cek, 128, $additional_header_values)
        );
    }

    #[Test]
    public function getAgreementKeyWithA256KeyWrap(): void
    {
        $additional_header_values = [
            'enc' => 'A256GCM',
        ];

        $sender = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
            'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
            'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
        ]);
        $receiver = new JWK([
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

        $ecdh_ss = new ECDHSSA256KW();
        $encrypted_cek = $ecdh_ss->wrapAgreementKey(
            $receiver->toPublic(),
            $sender,
            $cek,
            128,
            $additional_header_values,
            $additional_header_values
        );
        static::assertArrayNotHasKey('epk', $additional_header_values);
        static::assertSame(
            $cek,
            $ecdh_ss->unwrapAgreementKey($sender->toPublic(), $receiver, $encrypted_cek, 128, $additional_header_values)
        );
    }
}

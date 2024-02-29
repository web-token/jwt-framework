<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\ContentEncryption\AESGCM;

use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const STR_PAD_LEFT;

/**
 * @internal
 */
final class AESGCMContentEncryptionTest extends TestCase
{
    #[Test]
    public function a128GCMEncryptAndDecrypt(): void
    {
        $header = Base64UrlSafe::encodeUnpadded(json_encode([
            'alg' => 'ECDH-ES',
            'enc' => 'A128GCM',
        ]));
        $tag = null;

        $algorithm = new A128GCM();

        $cek = random_bytes(128 / 8);
        $iv = random_bytes(96 / 8);
        $plaintext = 'Live long and Prosper.';

        $cyphertext = $algorithm->encryptContent($plaintext, $cek, $iv, null, $header, $tag);

        static::assertNotNull($tag);
        static::assertSame($plaintext, $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag));
    }

    #[Test]
    public function a192GCMEncryptAndDecrypt(): void
    {
        $header = Base64UrlSafe::encodeUnpadded(json_encode([
            'alg' => 'ECDH-ES',
            'enc' => 'A192GCM',
        ]));
        $tag = null;

        $algorithm = new A192GCM();

        $cek = random_bytes(192 / 8);
        $iv = random_bytes(96 / 8);
        $plaintext = 'Live long and Prosper.';

        $cyphertext = $algorithm->encryptContent($plaintext, $cek, $iv, null, $header, $tag);

        static::assertNotNull($tag);
        static::assertSame($plaintext, $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag));
    }

    #[Test]
    public function a256GCMEncryptAndDecrypt(): void
    {
        $header = Base64UrlSafe::encodeUnpadded(json_encode([
            'alg' => 'ECDH-ES',
            'enc' => 'A256GCM',
        ]));
        $tag = null;

        $algorithm = new A256GCM();

        $cek = random_bytes(256 / 8);
        $iv = random_bytes(96 / 8);
        $plaintext = 'Live long and Prosper.';

        $cyphertext = $algorithm->encryptContent($plaintext, $cek, $iv, null, $header, $tag);

        static::assertNotNull($tag);
        static::assertSame($plaintext, $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.1
     */
    #[Test]
    public function a256GCMDecryptTestVector(): void
    {
        $algorithm = new A256GCM();

        $header = Base64UrlSafe::encodeUnpadded(json_encode([
            'alg' => 'RSA-OAEP',
            'enc' => 'A256GCM',
        ]));
        $cek = $this->convertArrayToBinString(
            [
                177,
                161,
                244,
                128,
                84,
                143,
                225,
                115,
                63,
                180,
                3,
                255,
                107,
                154,
                212,
                246,
                138,
                7,
                110,
                91,
                112,
                46,
                34,
                105,
                47,
                130,
                203,
                46,
                122,
                234,
                64,
                252,
            ]
        );
        $iv = $this->convertArrayToBinString([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]);
        $tag = $this->convertArrayToBinString(
            [92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145]
        );
        $cyphertext = $this->convertArrayToBinString(
            [
                229,
                236,
                166,
                241,
                53,
                191,
                115,
                196,
                174,
                43,
                73,
                109,
                39,
                122,
                233,
                96,
                140,
                206,
                120,
                52,
                51,
                237,
                48,
                11,
                190,
                219,
                186,
                80,
                111,
                104,
                50,
                142,
                47,
                167,
                59,
                61,
                181,
                127,
                196,
                21,
                40,
                82,
                242,
                32,
                123,
                143,
                168,
                226,
                73,
                216,
                176,
                144,
                138,
                247,
                106,
                60,
                16,
                205,
                160,
                109,
                64,
                63,
                192,
            ]
        );
        $expected_plaintext = 'The true sign of intelligence is not knowledge but imagination.';

        static::assertSame('eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ', $header);
        static::assertSame(
            $expected_plaintext,
            $algorithm->decryptContent($cyphertext, $cek, $iv, null, $header, $tag)
        );
    }

    private function convertArrayToBinString(array $data): string
    {
        foreach ($data as $key => $value) {
            $data[$key] = mb_str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }

        return hex2bin(implode('', $data));
    }
}

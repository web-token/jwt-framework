<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use function sprintf;
use function strlen;

/**
 * @internal
 */
final class RSAOAEPEncryptedKeyLengthTest extends EncryptionTestCase
{
    #[DataProvider('dataAlgorithms')]
    #[Test]
    public function anEncryptedKeyLongerThanTheModulusIsRejected(RSA $algorithm): void
    {
        $privateKey = $this->getPrivateKey();
        $publicKey = $privateKey->toPublic();
        $cek = random_bytes(32);
        $encryptedKey = $this->encryptKey($algorithm, $publicKey, $cek);
        $block = $this->encryptKey($algorithm, $publicKey, 'x');

        static::assertSame(256, strlen($encryptedKey));
        static::assertSame($cek, $algorithm->decryptKey($privateKey, $encryptedKey, []));

        $invalidEncryptedKeys = [
            'a block appended' => $encryptedKey . $block,
            'a block prepended' => $block . $encryptedKey,
            'the key split over two blocks' => $this->encryptKey($algorithm, $publicKey, substr($cek, 0, 16))
                . $this->encryptKey($algorithm, $publicKey, substr($cek, 16)),
            'a zero byte prepended' => "\0" . $encryptedKey,
        ];
        foreach ($invalidEncryptedKeys as $name => $invalidEncryptedKey) {
            try {
                $algorithm->decryptKey($privateKey, $invalidEncryptedKey, []);
                static::fail(sprintf('The encrypted key "%s" has been decrypted.', $name));
            } catch (RuntimeException $e) {
                static::assertSame('Unable to decrypt', $e->getMessage(), $name);
            }
        }
    }

    #[Test]
    public function anEncryptedKeyShorterThanTheModulusIsLeftPadded(): void
    {
        $privateKey = $this->getPrivateKey();
        $algorithm = new RSAOAEP256();
        $cek = hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
        $encryptedKey = Base64UrlSafe::decodeNoPadding(
            'AMk2ffFRxcuyBdu-wDiQGNVpXD4JVg8FNc2xzV3RpjrfUyJeftqbkvKo62k5eRKJD3alg3L7NwgoBUewzc_B4_g2U2U1NMYx8U2EYUAPOZqcXc1PRcv03UNqmsDv-TIYe5-SUBSJ4m8VuAST3KQQZwCjcQqA_J2ejF97VSkD3DWuH0HfLJHGXi_7T_OOQmWZ9pDOJw3EQlvRLOf3YVIVjPatsSn5Vzg5--RuwIeWwpvanIEb13x4tJcTRosLxsci1Ifle7KyJewV3UeEEUHVeBTWmNhFVN2imLFC5uIQDxpPZv-2XknGBcvQaSNQjcQ-v_KlvHQVQ1hvAr6bzKJEbA'
        );

        static::assertSame($cek, $algorithm->decryptKey($privateKey, $encryptedKey, []));
        static::assertSame($cek, $algorithm->decryptKey($privateKey, substr($encryptedKey, 1), []));

        $this->expectException(RuntimeException::class);
        $algorithm->decryptKey($privateKey, '', []);
    }

    #[DataProvider('dataMaximumMessageLengths')]
    #[Test]
    public function aMessageThatDoesNotFitInOneBlockIsNotEncrypted(RSA $algorithm, int $maximumLength): void
    {
        $publicKey = $this->getPrivateKey()
            ->toPublic();

        static::assertSame(256, strlen($this->encryptKey($algorithm, $publicKey, '')));
        static::assertSame(256, strlen($this->encryptKey($algorithm, $publicKey, random_bytes($maximumLength))));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Message too long');
        $this->encryptKey($algorithm, $publicKey, random_bytes($maximumLength + 1));
    }

    #[Test]
    public function aCapturedEncryptedKeyCannotBeSplicedIntoAnotherToken(): void
    {
        $privateKey = $this->getPrivateKey();
        $publicKey = $privateKey->toPublic();
        $algorithm = new RSAOAEP256();
        $loader = $this->getJWELoaderFactory()
            ->create(['jwe_compact'], ['RSA-OAEP-256', 'A256GCM', 'A256CBC-HS512']);
        $jwe = $this->getJWEBuilderFactory()
            ->create(['RSA-OAEP-256', 'A256GCM'])
            ->create()
            ->withPayload('Live long and Prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP-256',
                'enc' => 'A256GCM',
            ])
            ->addRecipient($publicKey)
            ->build();
        $captured = $this->getJWESerializerManager()
            ->serialize('jwe_compact', $jwe, 0);

        static::assertSame(
            'Live long and Prosper.',
            $loader->loadAndDecryptWithKey($captured, $privateKey, $recipient)
                ->getPayload()
        );

        $capturedEncryptedKey = Base64UrlSafe::decodeNoPadding(explode('.', $captured)[1]);
        $prefix = random_bytes(31);
        $suffix = random_bytes(1);
        $cek = $prefix . $algorithm->decryptKey($privateKey, $capturedEncryptedKey, []) . $suffix;
        $header = Base64UrlSafe::encodeUnpadded('{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512"}');
        $iv = random_bytes(16);
        $tag = null;
        $ciphertext = (new A256CBCHS512())->encryptContent('Forged.', $cek, $iv, null, $header, $tag);
        $token = implode('.', [
            $header,
            Base64UrlSafe::encodeUnpadded(
                $this->encryptKey($algorithm, $publicKey, $prefix)
                . $capturedEncryptedKey
                . $this->encryptKey($algorithm, $publicKey, $suffix)
            ),
            Base64UrlSafe::encodeUnpadded($iv),
            Base64UrlSafe::encodeUnpadded($ciphertext),
            Base64UrlSafe::encodeUnpadded((string) $tag),
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to load and decrypt the token.');
        $loader->loadAndDecryptWithKey($token, $privateKey, $recipient);
    }

    public static function dataAlgorithms(): iterable
    {
        yield 'RSA-OAEP' => [new RSAOAEP()];
        yield 'RSA-OAEP-256' => [new RSAOAEP256()];
    }

    public static function dataMaximumMessageLengths(): iterable
    {
        yield 'RSA-OAEP' => [new RSAOAEP(), 214];
        yield 'RSA-OAEP-256' => [new RSAOAEP256(), 190];
    }

    private function encryptKey(RSA $algorithm, JWK $key, string $message): string
    {
        $additionalHeader = [];

        return $algorithm->encryptKey($key, $message, [], $additionalHeader);
    }

    private function getPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'RSA',
            'n' => 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
            'e' => 'AQAB',
            'd' => 'kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ',
            'p' => '1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0',
            'q' => 'wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc',
            'dp' => 'ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE',
            'dq' => 'Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis',
            'qi' => 'VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY',
        ]);
    }
}

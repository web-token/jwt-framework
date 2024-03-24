<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class JWEFlattenedTest extends EncryptionTestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     */
    #[Test]
    public function loadFlattenedJWE(): void
    {
        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create(['A128KW', 'A128CBC-HS256']);

        $loaded = $this->getJWESerializerManager()
            ->unserialize(
                '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}'
            );

        static::assertSame('A128KW', $loaded->getRecipient(0)->getHeaderParameter('alg'));
        static::assertSame('A128CBC-HS256', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertNull($loaded->getPayload());
        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet(), 0));
        static::assertSame('Live long and prosper.', $loaded->getPayload());
    }

    private function getSymmetricKeySet(): JWKSet
    {
        $keys = [
            'keys' => [
                [
                    'kid' => 'DIR_1',
                    'kty' => 'oct',
                    'k' => Base64UrlSafe::encodeUnpadded(
                        hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F')
                    ),
                ],
                [
                    'kty' => 'oct',
                    'k' => 'f5aN5V6iihwQVqP-tPNNtkIJNCwUb9-JukCIKkF0rNfxqxA771RJynYAT2xtzAP0MYaR7U5fMP_wvbRQq5l38Q',
                ],
                [
                    'kty' => 'oct',
                    'k' => 'GawgguFyGrWKav7AX4VKUg',
                ],
                [
                    'kty' => 'oct',
                    'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                ],
            ],
        ];

        return JWKSet::createFromKeyData($keys);
    }
}

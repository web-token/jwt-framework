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

namespace Jose\Tests\Component\Encryption;

use Base64Url\Base64Url;
use Jose\Component\Core\JWKSet;

/**
 * @group functional
 *
 * @internal
 */
class JWEFlattenedTest extends EncryptionTest
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     *
     * @test
     */
    public function loadFlattenedJWE(): void
    {
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['A128KW'], ['A128CBC-HS256'], ['DEF']);

        $loaded = $this->getJWESerializerManager()->unserialize('{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}');

        static::assertEquals('A128KW', $loaded->getRecipient(0)->getHeaderParameter('alg'));
        static::assertEquals('A128CBC-HS256', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertNull($loaded->getPayload());
        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet(), 0));
        static::assertEquals('Live long and prosper.', $loaded->getPayload());
    }

    private function getSymmetricKeySet(): JWKSet
    {
        $keys = ['keys' => [
            [
                'kid' => 'DIR_1',
                'kty' => 'oct',
                'k' => Base64Url::encode(hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F')),
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
        ]];

        return JWKSet::createFromKeyData($keys);
    }
}

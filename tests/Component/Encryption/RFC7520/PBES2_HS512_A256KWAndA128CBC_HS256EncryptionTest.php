<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption\RFC7520;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Tests\Component\Encryption\EncryptionTestCase;
use PHPUnit\Framework\Attributes\Test;
use const JSON_THROW_ON_ERROR;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.3
 *
 * @internal
 */
final class PBES2_HS512_A256KWAndA128CBC_HS256EncryptionTest extends EncryptionTestCase
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are
     * always different). The output given in the RFC is used and only decrypted.
     */
    #[Test]
    public function pBES2HS512A256KWAndA128CBCHS256Encryption(): void
    {
        $expected_payload = [
            'keys' => [
                [
                    'kty' => 'oct',
                    'kid' => '77c7e2b8-6e13-45cf-8672-617b5b45243a',
                    'use' => 'enc',
                    'alg' => 'A128GCM',
                    'k' => 'XctOhJAkA-pD9Lh7ZgW_2A',
                ], [
                    'kty' => 'oct',
                    'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
                    'use' => 'enc',
                    'alg' => 'A128KW',
                    'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
                ], [
                    'kty' => 'oct',
                    'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
                    'use' => 'enc',
                    'alg' => 'A256GCMKW',
                    'k' => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
                ],
            ],
        ];

        $private_key = new JWK([
            'kty' => 'oct',
            'use' => 'enc',
            'k' => Base64UrlSafe::encodeUnpadded("entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun"),
        ]);

        $protectedHeader = [
            'alg' => 'PBES2-HS512+A256KW',
            'p2s' => '8Q1SzinasR3xchYz6ZZcHA',
            'p2c' => 8192,
            'cty' => 'jwk-set+json',
            'enc' => 'A128CBC-HS256',
        ];

        $expected_compact_json = 'eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g.VBiCzVHNoLiR3F4V82uoTQ.23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p.0HlwodAhOCILG5SQ2LQ9dg';
        $expected_flattened_json = '{"protected":"eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g","iv":"VBiCzVHNoLiR3F4V82uoTQ","ciphertext":"23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p","tag":"0HlwodAhOCILG5SQ2LQ9dg"}';
        $expected_json = '{"recipients":[{"encrypted_key":"d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g"}],"protected":"eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","iv":"VBiCzVHNoLiR3F4V82uoTQ","ciphertext":"23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p","tag":"0HlwodAhOCILG5SQ2LQ9dg"}';
        $expected_iv = 'VBiCzVHNoLiR3F4V82uoTQ';
        $expected_encrypted_key = 'd3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g';
        $expected_ciphertext = '23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p';
        $expected_tag = '0HlwodAhOCILG5SQ2LQ9dg';

        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create(['PBES2-HS512+A256KW', 'A128CBC-HS256']);

        $loaded_compact_json = $this->getJWESerializerManager()
            ->unserialize($expected_compact_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_compact_json, $private_key, 0));

        $loaded_flattened_json = $this->getJWESerializerManager()
            ->unserialize($expected_flattened_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()
            ->unserialize($expected_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertSame($expected_ciphertext, Base64UrlSafe::encodeUnpadded($loaded_compact_json->getCiphertext()));
        static::assertSame($protectedHeader, $loaded_compact_json->getSharedProtectedHeader());
        static::assertSame($expected_iv, Base64UrlSafe::encodeUnpadded($loaded_compact_json->getIV()));
        static::assertSame(
            $expected_encrypted_key,
            Base64UrlSafe::encodeUnpadded($loaded_compact_json->getRecipient(0)->getEncryptedKey())
        );
        static::assertSame($expected_tag, Base64UrlSafe::encodeUnpadded($loaded_compact_json->getTag()));

        static::assertSame(
            $expected_ciphertext,
            Base64UrlSafe::encodeUnpadded($loaded_flattened_json->getCiphertext())
        );
        static::assertSame($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        static::assertSame($expected_iv, Base64UrlSafe::encodeUnpadded($loaded_flattened_json->getIV()));
        static::assertSame(
            $expected_encrypted_key,
            Base64UrlSafe::encodeUnpadded($loaded_flattened_json->getRecipient(0)->getEncryptedKey())
        );
        static::assertSame($expected_tag, Base64UrlSafe::encodeUnpadded($loaded_flattened_json->getTag()));

        static::assertSame($expected_ciphertext, Base64UrlSafe::encodeUnpadded($loaded_json->getCiphertext()));
        static::assertSame($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertSame($expected_iv, Base64UrlSafe::encodeUnpadded($loaded_json->getIV()));
        static::assertSame(
            $expected_encrypted_key,
            Base64UrlSafe::encodeUnpadded($loaded_json->getRecipient(0)->getEncryptedKey())
        );
        static::assertSame($expected_tag, Base64UrlSafe::encodeUnpadded($loaded_json->getTag()));

        static::assertSame(
            $expected_payload,
            json_decode((string) $loaded_compact_json->getPayload(), true, 512, JSON_THROW_ON_ERROR)
        );
        static::assertSame(
            $expected_payload,
            json_decode((string) $loaded_flattened_json->getPayload(), true, 512, JSON_THROW_ON_ERROR)
        );
        static::assertSame(
            $expected_payload,
            json_decode((string) $loaded_json->getPayload(), true, 512, JSON_THROW_ON_ERROR)
        );
    }

    /**
     * Same input as before, but we perform the encryption first.
     */
    #[Test]
    public function pBES2HS512A256KWAndA128CBCHS256EncryptionBis(): void
    {
        $expected_payload = json_encode([
            'keys' => [
                [
                    'kty' => 'oct',
                    'kid' => '77c7e2b8-6e13-45cf-8672-617b5b45243a',
                    'use' => 'enc',
                    'alg' => 'A128GCM',
                    'k' => 'XctOhJAkA-pD9Lh7ZgW_2A',
                ], [
                    'kty' => 'oct',
                    'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
                    'use' => 'enc',
                    'alg' => 'A128KW',
                    'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
                ], [
                    'kty' => 'oct',
                    'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
                    'use' => 'enc',
                    'alg' => 'A256GCMKW',
                    'k' => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
                ],
            ],
        ]);

        $private_key = new JWK([
            'kty' => 'oct',
            'use' => 'enc',
            'k' => Base64UrlSafe::encodeUnpadded("entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun"),
        ]);

        $protectedHeader = [
            'alg' => 'PBES2-HS512+A256KW',
            'cty' => 'jwk-set+json',
            'enc' => 'A128CBC-HS256',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['PBES2-HS512+A256KW', 'A128CBC-HS256']);
        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create(['PBES2-HS512+A256KW', 'A128CBC-HS256']);

        $jwe = $jweBuilder
            ->create()
            ->withPayload($expected_payload)
            ->withSharedProtectedHeader($protectedHeader)
            ->addRecipient($private_key)
            ->build();

        $loaded_flattened_json = $this->getJWESerializerManager()
            ->unserialize($this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()
            ->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertArrayHasKey('p2s', $loaded_flattened_json->getSharedProtectedHeader());
        static::assertArrayHasKey('p2c', $loaded_flattened_json->getSharedProtectedHeader());

        static::assertArrayHasKey('p2s', $loaded_json->getSharedProtectedHeader());
        static::assertArrayHasKey('p2c', $loaded_json->getSharedProtectedHeader());

        static::assertSame($expected_payload, $loaded_flattened_json->getPayload());
        static::assertSame($expected_payload, $loaded_json->getPayload());
    }
}

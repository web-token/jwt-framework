<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption\RFC7520;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Tests\Component\Encryption\EncryptionTestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.11
 *
 * @internal
 */
final class A128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValuesTest extends EncryptionTestCase
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are
     * always different). The output given in the RFC is used and only decrypted.
     */
    #[Test]
    public function a128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValues(): void
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);

        $protectedHeader = [
            'enc' => 'A128GCM',
        ];

        $header = [
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
        ];

        $expected_flattened_json = '{"protected":"eyJlbmMiOiJBMTI4R0NNIn0","unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8"},"encrypted_key":"jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H","iv":"WgEJsDS9bkoXQ3nR","ciphertext":"lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf","tag":"fNYLqpUe84KD45lvDiaBAQ"}';
        $expected_json = '{"recipients":[{"encrypted_key":"jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H"}],"unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8"},"protected":"eyJlbmMiOiJBMTI4R0NNIn0","iv":"WgEJsDS9bkoXQ3nR","ciphertext":"lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf","tag":"fNYLqpUe84KD45lvDiaBAQ"}';
        $expected_iv = 'WgEJsDS9bkoXQ3nR';
        $expected_encrypted_key = 'jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H';
        $expected_ciphertext = 'lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf';
        $expected_tag = 'fNYLqpUe84KD45lvDiaBAQ';

        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create(['A128KW', 'A128GCM']);

        $loaded_flattened_json = $this->getJWESerializerManager()
            ->unserialize($expected_flattened_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()
            ->unserialize($expected_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

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
        static::assertSame($header, $loaded_flattened_json->getSharedHeader());
        static::assertSame($expected_tag, Base64UrlSafe::encodeUnpadded($loaded_flattened_json->getTag()));

        static::assertSame($expected_ciphertext, Base64UrlSafe::encodeUnpadded($loaded_json->getCiphertext()));
        static::assertSame($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertSame($expected_iv, Base64UrlSafe::encodeUnpadded($loaded_json->getIV()));
        static::assertSame(
            $expected_encrypted_key,
            Base64UrlSafe::encodeUnpadded($loaded_json->getRecipient(0)->getEncryptedKey())
        );
        static::assertSame($header, $loaded_json->getSharedHeader());
        static::assertSame($expected_tag, Base64UrlSafe::encodeUnpadded($loaded_json->getTag()));

        static::assertSame($expected_payload, $loaded_flattened_json->getPayload());
        static::assertSame($expected_payload, $loaded_json->getPayload());
    }

    /**
     * Same input as before, but we perform the encryption first.
     */
    #[Test]
    public function a128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValuesBis(): void
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);

        $protectedHeader = [
            'enc' => 'A128GCM',
        ];

        $header = [
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128GCM']);
        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create(['A128KW', 'A128GCM']);

        $jwe = $jweBuilder
            ->create()
            ->withPayload($expected_payload)
            ->withSharedProtectedHeader($protectedHeader)
            ->withSharedHeader($header)
            ->addRecipient($private_key)
            ->build();

        $loaded_flattened_json = $this->getJWESerializerManager()
            ->unserialize($this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()
            ->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertSame($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        static::assertSame($header, $loaded_flattened_json->getSharedHeader());

        static::assertSame($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertSame($header, $loaded_json->getSharedHeader());

        static::assertSame($expected_payload, $loaded_flattened_json->getPayload());
        static::assertSame($expected_payload, $loaded_json->getPayload());
    }
}

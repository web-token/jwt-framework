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

namespace Jose\Component\Encryption\Tests\RFC7520;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Tests\EncryptionTest;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.11
 *
 * @group RFC7520
 */
final class A128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValuesTest extends EncryptionTest
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are always different).
     * The output given in the RFC is used and only decrypted.
     */
    public function testA128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValues()
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = JWK::create([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k'   => 'GZy6sIZ6wl9NJOKB-jnmVQ',
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

        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['A128KW'], ['A128GCM'], ['DEF']);

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($expected_flattened_json);
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($expected_json);
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        self::assertEquals($expected_ciphertext, Base64Url::encode($loaded_flattened_json->getCiphertext()));
        self::assertEquals($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        self::assertEquals($expected_iv, Base64Url::encode($loaded_flattened_json->getIV()));
        self::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_flattened_json->getRecipient(0)->getEncryptedKey()));
        self::assertEquals($header, $loaded_flattened_json->getSharedHeader());
        self::assertEquals($expected_tag, Base64Url::encode($loaded_flattened_json->getTag()));

        self::assertEquals($expected_ciphertext, Base64Url::encode($loaded_json->getCiphertext()));
        self::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());
        self::assertEquals($expected_iv, Base64Url::encode($loaded_json->getIV()));
        self::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_json->getRecipient(0)->getEncryptedKey()));
        self::assertEquals($header, $loaded_json->getSharedHeader());
        self::assertEquals($expected_tag, Base64Url::encode($loaded_json->getTag()));

        self::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        self::assertEquals($expected_payload, $loaded_json->getPayload());
    }

    /**
     * Same input as before, but we perform the encryption first.
     */
    public function testA128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValuesBis()
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = JWK::create([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k'   => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);

        $protectedHeader = [
            'enc' => 'A128GCM',
        ];

        $header = [
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()->create(['A128KW'], ['A128GCM'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['A128KW'], ['A128GCM'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload($expected_payload)
            ->withSharedProtectedHeader($protectedHeader)
            ->withSharedHeader($header)
            ->addRecipient($private_key)
            ->build();

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0));
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        self::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        self::assertEquals($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        self::assertEquals($header, $loaded_flattened_json->getSharedHeader());

        self::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());
        self::assertEquals($header, $loaded_json->getSharedHeader());

        self::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        self::assertEquals($expected_payload, $loaded_json->getPayload());
    }
}

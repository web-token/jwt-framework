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

namespace Jose\Tests\Component\Encryption\RFC7520;

use function array_key_exists;
use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Tests\Component\Encryption\EncryptionTest;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.7
 *
 * @group RFC7520
 *
 * @internal
 */
class A256GCMKWAndA128CBC_HS256EncryptionTest extends EncryptionTest
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are always different).
     * The output given in the RFC is used and only decrypted.
     *
     * @test
     */
    public function a256GCMKWAndA128CBCHS256Encryption(): void
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'oct',
            'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
            'use' => 'enc',
            'alg' => 'A256GCMKW',
            'k' => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
        ]);

        $protectedHeader = [
            'alg' => 'A256GCMKW',
            'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
            'tag' => 'kfPduVQ3T3H6vnewt--ksw',
            'iv' => 'KkYT0GX_2jHlfqN_',
            'enc' => 'A128CBC-HS256',
        ];

        $expected_compact_json = 'eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYjIwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9.lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok.gz6NjyEFNm_vm8Gj6FwoFQ.Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaEeVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCzLjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFqhpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hdeb6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0JtjxAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR1B-gxpNk3xWU.DKW7jrb4WaRSNfbXVPlT5g';

        /*
         * There is an error in this vector
         * In the RFC7520, the tag is 'DKW7jrb4WaRSNfbXVPlT5g' (see figure 147), but the tag from the flattened representation is 'NvBveHr_vonkvflfnUrmBQ'
         * Same goes for the protected header. The values are good, but as the order is different, the protected header value is different and the tag is not validated.
         */
        $expected_flattened_json = '{"protected":"eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYjIwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9","encrypted_key":"lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok","iv":"gz6NjyEFNm_vm8Gj6FwoFQ","ciphertext":"Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaEeVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCzLjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFqhpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hdeb6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0JtjxAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR1B-gxpNk3xWU","tag":"DKW7jrb4WaRSNfbXVPlT5g"}';
        $expected_json = '{"recipients":[{"encrypted_key":"lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok"}],"protected":"eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYjIwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9","iv":"gz6NjyEFNm_vm8Gj6FwoFQ","ciphertext":"Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaEeVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCzLjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFqhpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hdeb6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0JtjxAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR1B-gxpNk3xWU","tag":"DKW7jrb4WaRSNfbXVPlT5g"}';
        $expected_iv = 'gz6NjyEFNm_vm8Gj6FwoFQ';
        $expected_encrypted_key = 'lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok';
        $expected_ciphertext = 'Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaEeVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCzLjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFqhpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hdeb6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0JtjxAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR1B-gxpNk3xWU';
        $expected_tag = 'DKW7jrb4WaRSNfbXVPlT5g';

        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['A256GCMKW'], ['A128CBC-HS256'], ['DEF']);

        $loaded_compact_json = $this->getJWESerializerManager()->unserialize($expected_compact_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_compact_json, $private_key, 0));

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($expected_flattened_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($expected_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_compact_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_compact_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_compact_json->getIV()));
        static::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_compact_json->getRecipient(0)->getEncryptedKey()));
        static::assertEquals($expected_tag, Base64Url::encode($loaded_compact_json->getTag()));

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_flattened_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_flattened_json->getIV()));
        static::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_flattened_json->getRecipient(0)->getEncryptedKey()));
        static::assertEquals($expected_tag, Base64Url::encode($loaded_flattened_json->getTag()));

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_json->getIV()));
        static::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_json->getRecipient(0)->getEncryptedKey()));
        static::assertEquals($expected_tag, Base64Url::encode($loaded_json->getTag()));

        static::assertEquals($expected_payload, $loaded_compact_json->getPayload());
        static::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        static::assertEquals($expected_payload, $loaded_json->getPayload());
    }

    /**
     * Same input as before, but we perform the encryption first.
     *
     * @test
     */
    public function a256GCMKWAndA128CBCHS256EncryptionBis(): void
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'oct',
            'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
            'use' => 'enc',
            'alg' => 'A256GCMKW',
            'k' => 'qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8',
        ]);

        $protectedHeader = [
            'alg' => 'A256GCMKW',
            'kid' => '18ec08e1-bfa9-4d95-b205-2b4dd1d4321d',
            'enc' => 'A128CBC-HS256',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()->create(['A256GCMKW'], ['A128CBC-HS256'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['A256GCMKW'], ['A128CBC-HS256'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload($expected_payload)
            ->withSharedProtectedHeader($protectedHeader)
            ->addRecipient($private_key)
            ->build()
        ;

        $loaded_compact_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_compact', $jwe, 0));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_compact_json, $private_key, 0));

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertTrue(array_key_exists('iv', $loaded_compact_json->getSharedProtectedHeader()));
        static::assertTrue(array_key_exists('tag', $loaded_compact_json->getSharedProtectedHeader()));

        static::assertTrue(array_key_exists('iv', $loaded_flattened_json->getSharedProtectedHeader()));
        static::assertTrue(array_key_exists('tag', $loaded_flattened_json->getSharedProtectedHeader()));

        static::assertTrue(array_key_exists('iv', $loaded_json->getSharedProtectedHeader()));
        static::assertTrue(array_key_exists('tag', $loaded_json->getSharedProtectedHeader()));

        static::assertEquals($expected_payload, $loaded_compact_json->getPayload());
        static::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        static::assertEquals($expected_payload, $loaded_json->getPayload());
    }
}

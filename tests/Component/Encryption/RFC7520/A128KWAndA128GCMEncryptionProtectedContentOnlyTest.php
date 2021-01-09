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

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Tests\Component\Encryption\EncryptionTest;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.12
 *
 * @group RFC7520
 *
 * @internal
 */
class A128KWAndA128GCMEncryptionProtectedContentOnlyTest extends EncryptionTest
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are always different).
     * The output given in the RFC is used and only decrypted.
     *
     * @test
     */
    public function a128KWAndA128GCMEncryptionProtectedContentOnly(): void
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
        ];

        $header = [
            'enc' => 'A128GCM',
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
        ];

        $expected_flattened_json = '{"unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8","enc":"A128GCM"},"encrypted_key":"244YHfO_W7RMpQW81UjQrZcq5LSyqiPv","iv":"YihBoVOGsR1l7jCD","ciphertext":"qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHFSP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDsRPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDfrb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4-8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF","tag":"e2m0Vm7JvjK2VpCKXS-kyg"}';
        $expected_json = '{"recipients":[{"encrypted_key":"244YHfO_W7RMpQW81UjQrZcq5LSyqiPv"}],"unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8","enc":"A128GCM"},"iv":"YihBoVOGsR1l7jCD","ciphertext":"qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHFSP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDsRPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDfrb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4-8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF","tag":"e2m0Vm7JvjK2VpCKXS-kyg"}';
        $expected_iv = 'YihBoVOGsR1l7jCD';
        $expected_encrypted_key = '244YHfO_W7RMpQW81UjQrZcq5LSyqiPv';
        $expected_ciphertext = 'qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHFSP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDsRPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDfrb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4-8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF';
        $expected_tag = 'e2m0Vm7JvjK2VpCKXS-kyg';

        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['A128KW'], ['A128GCM'], ['DEF']);

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($expected_flattened_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($expected_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_flattened_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_flattened_json->getIV()));
        static::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_flattened_json->getRecipient(0)->getEncryptedKey()));
        static::assertEquals($header, $loaded_flattened_json->getSharedHeader());
        static::assertEquals($expected_tag, Base64Url::encode($loaded_flattened_json->getTag()));

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_json->getIV()));
        static::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_json->getRecipient(0)->getEncryptedKey()));
        static::assertEquals($header, $loaded_json->getSharedHeader());
        static::assertEquals($expected_tag, Base64Url::encode($loaded_json->getTag()));

        static::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        static::assertEquals($expected_payload, $loaded_json->getPayload());
    }

    /**
     * Same input as before, but we perform the encryption first.
     *
     * @test
     */
    public function a128KWAndA128GCMEncryptionProtectedContentOnlyBis(): void
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
        ];

        $header = [
            'enc' => 'A128GCM',
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
            ->build()
        ;

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertEquals($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        static::assertEquals($header, $loaded_flattened_json->getSharedHeader());

        static::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertEquals($header, $loaded_json->getSharedHeader());

        static::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        static::assertEquals($expected_payload, $loaded_json->getPayload());
    }
}

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
 * @see https://tools.ietf.org/html/rfc7520#section-5.5
 *
 * @group RFC7520
 *
 * @internal
 */
class ECDH_ES_AndA128CBC_HS256EncryptionTest extends EncryptionTest
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are always different).
     * The output given in the RFC is used and only decrypted.
     *
     * @test
     */
    public function eCDHESAndA128CBCHS256Encryption(): void
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'EC',
            'kid' => 'meriadoc.brandybuck@buckland.example',
            'use' => 'enc',
            'crv' => 'P-256',
            'x' => 'Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0',
            'y' => 'HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw',
            'd' => 'r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8',
        ]);

        $protectedHeader = [
            'alg' => 'ECDH-ES',
            'kid' => 'meriadoc.brandybuck@buckland.example',
            'epk' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA',
                'y' => '8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs',
            ],
            'enc' => 'A128CBC-HS256',
        ];

        $expected_compact_json = 'eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidWNrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZFlvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ..yc9N8v5sYyv3iGQT926IUg.BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_evAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ6195_JGG2m9Csg.WCCkNa-x4BeB9hIDIfFuhg';
        $expected_json = '{"protected":"eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidWNrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZFlvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ","iv":"yc9N8v5sYyv3iGQT926IUg","ciphertext":"BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_evAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ6195_JGG2m9Csg","tag":"WCCkNa-x4BeB9hIDIfFuhg"}';
        $expected_iv = 'yc9N8v5sYyv3iGQT926IUg';
        $expected_ciphertext = 'BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_evAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ6195_JGG2m9Csg';
        $expected_tag = 'WCCkNa-x4BeB9hIDIfFuhg';

        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['ECDH-ES'], ['A128CBC-HS256'], ['DEF']);

        $loaded_compact_json = $this->getJWESerializerManager()->unserialize($expected_compact_json);

        $loaded_json = $this->getJWESerializerManager()->unserialize($expected_json);

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_compact_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_compact_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_compact_json->getIV()));
        static::assertEquals($expected_tag, Base64Url::encode($loaded_compact_json->getTag()));

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_json->getIV()));
        static::assertEquals($expected_tag, Base64Url::encode($loaded_json->getTag()));

        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_compact_json, $private_key, 0));
        static::assertEquals($expected_payload, $loaded_compact_json->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));
        static::assertEquals($expected_payload, $loaded_json->getPayload());
    }

    /**
     * Same input as before, but we perform the encryption first.
     *
     * @test
     */
    public function eCDHESAndA128CBCHS256EncryptionBis(): void
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $public_key = new JWK([
            'kty' => 'EC',
            'kid' => 'meriadoc.brandybuck@buckland.example',
            'use' => 'enc',
            'crv' => 'P-256',
            'x' => 'Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0',
            'y' => 'HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw',
        ]);

        $private_key = new JWK([
            'kty' => 'EC',
            'kid' => 'meriadoc.brandybuck@buckland.example',
            'use' => 'enc',
            'crv' => 'P-256',
            'x' => 'Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0',
            'y' => 'HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw',
            'd' => 'r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8',
        ]);

        $protectedHeader = [
            'alg' => 'ECDH-ES',
            'kid' => 'meriadoc.brandybuck@buckland.example',
            'enc' => 'A128CBC-HS256',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()->create(['ECDH-ES'], ['A128CBC-HS256'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['ECDH-ES'], ['A128CBC-HS256'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload($expected_payload)
            ->withSharedProtectedHeader($protectedHeader)
            ->addRecipient($public_key)
            ->build()
        ;

        $loaded_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertTrue(array_key_exists('epk', $loaded_json->getSharedProtectedHeader()));

        static::assertEquals($expected_payload, $loaded_json->getPayload());
    }
}

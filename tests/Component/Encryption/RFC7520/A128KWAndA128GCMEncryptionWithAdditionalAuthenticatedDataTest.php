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
 * @see https://tools.ietf.org/html/rfc7520#section-5.10
 *
 * @group RFC7520
 *
 * @internal
 */
class A128KWAndA128GCMEncryptionWithAdditionalAuthenticatedDataTest extends EncryptionTest
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are always different).
     * The output given in the RFC is used and only decrypted.
     *
     * @test
     */
    public function a128KWAndA128GCMEncryptionWithAdditionalAuthenticatedData(): void
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
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'enc' => 'A128GCM',
        ];

        $expected_flattened_json = '{"protected":"eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X","aad":"WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fSwidGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0IixbIkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LCJ0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d","iv":"veCx9ece2orS7c_N","ciphertext":"Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0Ui8p74SchQP8xygM1oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14T_4NFqF-p2Mx8zkbKxI7oPK8KNarFbyxIDvICNqBLba-v3uzXBdB89fzOI-Lv4PjOFAQGHrgv1rjXAmKbgkft9cB4WeyZw8MldbBhc-V_KWZslrsLNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4aq3FXBxOxCys35PhCdaggy2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHrRDQeHyMRoBljoV3X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV","tag":"vOaH_Rajnpy_3hOtqvZHRA"}';
        $expected_json = '{"recipients":[{"encrypted_key":"4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X"}],"protected":"eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0","iv":"veCx9ece2orS7c_N","aad":"WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fSwidGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0IixbIkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LCJ0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d","ciphertext":"Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0Ui8p74SchQP8xygM1oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14T_4NFqF-p2Mx8zkbKxI7oPK8KNarFbyxIDvICNqBLba-v3uzXBdB89fzOI-Lv4PjOFAQGHrgv1rjXAmKbgkft9cB4WeyZw8MldbBhc-V_KWZslrsLNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4aq3FXBxOxCys35PhCdaggy2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHrRDQeHyMRoBljoV3X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV","tag":"vOaH_Rajnpy_3hOtqvZHRA"}';
        $expected_iv = 'veCx9ece2orS7c_N';
        $expected_aad = '["vcard",[["version",{},"text","4.0"],["fn",{},"text","Meriadoc Brandybuck"],["n",{},"text",["Brandybuck","Meriadoc","Mr.",""]],["bday",{},"text","TA 2982"],["gender",{},"text","M"]]]';
        $expected_encrypted_key = '4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X';
        $expected_ciphertext = 'Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0Ui8p74SchQP8xygM1oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14T_4NFqF-p2Mx8zkbKxI7oPK8KNarFbyxIDvICNqBLba-v3uzXBdB89fzOI-Lv4PjOFAQGHrgv1rjXAmKbgkft9cB4WeyZw8MldbBhc-V_KWZslrsLNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4aq3FXBxOxCys35PhCdaggy2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHrRDQeHyMRoBljoV3X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV';
        $expected_tag = 'vOaH_Rajnpy_3hOtqvZHRA';

        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['A128KW'], ['A128GCM'], ['DEF']);

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($expected_flattened_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($expected_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_flattened_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_flattened_json->getIV()));
        static::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_flattened_json->getRecipient(0)->getEncryptedKey()));
        static::assertEquals($expected_tag, Base64Url::encode($loaded_flattened_json->getTag()));
        static::assertEquals($expected_aad, $loaded_flattened_json->getAAD());

        static::assertEquals($expected_ciphertext, Base64Url::encode($loaded_json->getCiphertext()));
        static::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertEquals($expected_iv, Base64Url::encode($loaded_json->getIV()));
        static::assertEquals($expected_encrypted_key, Base64Url::encode($loaded_json->getRecipient(0)->getEncryptedKey()));
        static::assertEquals($expected_tag, Base64Url::encode($loaded_json->getTag()));
        static::assertEquals($expected_aad, $loaded_json->getAAD());

        static::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        static::assertEquals($expected_payload, $loaded_json->getPayload());
    }

    /**
     * Same input as before, but we perform the encryption first.
     *
     * @test
     */
    public function a128KWAndA128GCMEncryptionWithAdditionalAuthenticatedDataBis(): void
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
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'enc' => 'A128GCM',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()->create(['A128KW'], ['A128GCM'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['A128KW'], ['A128GCM'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload($expected_payload)
            ->withSharedProtectedHeader($protectedHeader)
            ->addRecipient($private_key)
            ->build()
        ;

        $loaded_flattened_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertEquals($protectedHeader, $loaded_flattened_json->getSharedProtectedHeader());

        static::assertEquals($protectedHeader, $loaded_json->getSharedProtectedHeader());

        static::assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        static::assertEquals($expected_payload, $loaded_json->getPayload());
    }
}

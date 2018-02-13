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

namespace Jose\Component\Encryption\Tests;

use Jose\Component\Core\JWK;

/**
 * Class ECDHESWithX25519EncryptionTest.
 *
 * @group ECDHES
 * @group Unit
 */
final class ECDHESWithX25519EncryptionTest extends EncryptionTest
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-B
     */
    public function testA128CBCHS256EncryptAndDecrypt()
    {
        $receiverKey = JWK::create([
            'kty' => 'OKP',
            'crv' => 'X25519',
            'x'   => 'azBwhSxIIhQIri4QdT__5q7ybEhKItJlGeyuLNN5ZCQ',
            'd'   => 'aCaXuAvPEuLVqQSihzryIWaQqmXZxA-3ZrF6CEm180c',
        ]);
        $input = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $protectedHeader = [
            'alg' => 'ECDH-ES+A128KW',
            'enc' => 'A128GCM',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()->create(['ECDH-ES+A128KW'], ['A128GCM'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['ECDH-ES+A128KW'], ['A128GCM'], ['DEF']);

        $jwt = $jweBuilder
            ->create()->withPayload($input)
            ->withSharedProtectedHeader($protectedHeader)
            ->addRecipient($receiverKey)
            ->build();
        $jwt = $this->getJWESerializerManager()->serialize('jwe_compact', $jwt, 0);

        $jwe = $this->getJWESerializerManager()->unserialize($jwt);
        self::assertTrue($jweDecrypter->decryptUsingKey($jwe, $receiverKey, 0));
        self::assertTrue($jwe->hasSharedProtectedHeaderParameter('epk'));
        self::assertEquals($input, $jwe->getPayload());
    }
}

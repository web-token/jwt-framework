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

use Jose\Component\Core\JWK;

/**
 * Class ECDHESWithX25519EncryptionTest.
 *
 * @group ECDHES
 * @group unit
 *
 * @internal
 */
class ECDHESWithX25519EncryptionTest extends EncryptionTest
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-B
     *
     * @test
     */
    public function a128CBCHS256EncryptAndDecrypt(): void
    {
        $receiverKey = new JWK([
            'kty' => 'OKP',
            'crv' => 'X25519',
            'x' => 'azBwhSxIIhQIri4QdT__5q7ybEhKItJlGeyuLNN5ZCQ',
            'd' => 'aCaXuAvPEuLVqQSihzryIWaQqmXZxA-3ZrF6CEm180c',
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
            ->build()
        ;
        $jwt = $this->getJWESerializerManager()->serialize('jwe_compact', $jwt, 0);

        $jwe = $this->getJWESerializerManager()->unserialize($jwt);
        static::assertTrue($jweDecrypter->decryptUsingKey($jwe, $receiverKey, 0));
        static::assertTrue($jwe->hasSharedProtectedHeaderParameter('epk'));
        static::assertEquals($input, $jwe->getPayload());
    }
}

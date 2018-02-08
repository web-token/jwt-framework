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

namespace Jose\Component\Signature\Tests\RFC7520;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Tests\SignatureTest;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-4.3
 *
 * @group RFC7520
 */
class ECDSASignatureTest extends SignatureTest
{
    /**
     * Please note that we cannot create the signature and get the same result as the example (ECDSA signatures are always different).
     * This test case create a signature and verifies it.
     * Then the output given in the RFC is used and verified.
     * This way, we can say that the library is able to create/verify ECDSA signatures and verify signature from test vectors.
     */
    public function testES512()
    {
        /*
         * Payload
         * EC public key
         * @see https://tools.ietf.org/html/rfc7520#section-3.2
         * @see https://tools.ietf.org/html/rfc7520#section-4.3.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $private_key = JWK::create([
            'kty' => 'EC',
            'kid' => 'bilbo.baggins@hobbiton.example',
            'use' => 'sig',
            'crv' => 'P-521',
            'x'   => 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt',
            'y'   => 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1',
            'd'   => 'AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt',
        ]);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.3.2
         */
        $header = [
            'alg' => 'ES512',
            'kid' => 'bilbo.baggins@hobbiton.example',
        ];

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['ES512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['ES512']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload)
            ->addSignature($private_key, $header)
            ->build();

        self::assertTrue($jwsVerifier->verifyWithKey($jws, $private_key, 0));

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.3.3
         */
        $expected_compact_json = 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2';
        $expected_flattened_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","protected":"eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9","signature":"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"}';
        $expected_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"protected":"eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9","signature":"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"}]}';

        $loaded_compact_json = $this->getJWSSerializerManager()->unserialize($expected_compact_json);
        self::assertTrue($jwsVerifier->verifyWithKey($loaded_compact_json, $private_key, 0));

        $loaded_flattened_json = $this->getJWSSerializerManager()->unserialize($expected_flattened_json);
        self::assertTrue($jwsVerifier->verifyWithKey($loaded_flattened_json, $private_key, 0));

        $loaded_json = $this->getJWSSerializerManager()->unserialize($expected_json);
        self::assertTrue($jwsVerifier->verifyWithKey($loaded_json, $private_key, 0));
    }
}

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

namespace Jose\Component\Signature\Tests;

use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;

/**
 * @group JWS
 */
class JWSSplitTest extends SignatureTest
{
    /**
     * @test
     */
    public function aJwsObjectWithMoreThanOneRecipientCanBeSplittedIntoSeveralJwsObjects()
    {
        $input = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"bilbo.baggins@hobbiton.example"},"signature":"MIsjqtVlOpa71KE-Mss8_Nq2YH4FGhiocsqrgi5NvyG53uoimic1tcMdSg-qptrzZc7CG6Svw2Y13TDIqHzTUrL_lR2ZFcryNFiHkSw129EghGpwkpxaTn_THJTCglNbADko1MZBCdwzJxwqZc-1RlpO2HibUYyXSwO97BSe0_evZKdjvvKSgsIqjytKSeAMbhMBdMma622_BG5t4sdbuCHtFjp9iJmkio47AIwqkZV1aIZsv33uPUqBBCXbYoQJwt7mxPftHmNlGoOSMxR_3thmXTCm4US-xiNOyhbm8afKK64jU6_TPtQHiJeQJxz9G3Tx-083B745_AfYOnlC9w"},{"header":{"alg":"ES512","kid":"bilbo.baggins@hobbiton.example"},"signature":"ARcVLnaJJaUWG8fG-8t5BREVAuTY8n8YHjwDO1muhcdCoFZFFjfISu0Cdkn9Ybdlmi54ho0x924DUz8sK7ZXkhc7AFM8ObLfTvNCrqcI3Jkl2U5IX3utNhODH6v7xgy1Qahsn0fyb4zSAkje8bAWz4vIfj5pCMYxxm4fgV3q7ZYhm5eD"},{"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}]}';
        $serializer = new JSONGeneralSerializer(new StandardConverter());
        $jws = $serializer->unserialize($input);
        $split = $jws->split();

        self::assertEquals(3, $jws->countSignatures());
        self::assertEquals(3, count($jws->split()));

        for ($i = 0; $i < $jws->countSignatures(); $i++) {
            $signature1 = $jws->getSignature($i);
            $tempJws = $split[$i];
            self::assertEquals(1, $tempJws->countSignatures());
            self::assertEquals($jws->isPayloadDetached(), $tempJws->isPayloadDetached());
            self::assertEquals($jws->getEncodedPayload(), $tempJws->getEncodedPayload());
            self::assertEquals($jws->getPayload(), $tempJws->getPayload());

            $signature2 = $tempJws->getSignature(0);
            self::assertEquals($signature1->getSignature(), $signature2->getSignature());
            self::assertEquals($signature1->getHeader(), $signature2->getHeader());
            self::assertEquals($signature1->getEncodedProtectedHeader(), $signature2->getEncodedProtectedHeader());
            self::assertEquals($signature1->getProtectedHeader(), $signature2->getProtectedHeader());
        }
    }
}

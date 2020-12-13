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
 * @group CVE
 * @group functional
 *
 * @internal
 */
class InvalidCurveAttackTest extends EncryptionTest
{
    /**
     * @test
     */
    public function curveCheckNegativeP256AttackPt1(): void
    {
        $maliciousJWE = 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0.qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg.pEA5kX304PMCOmFSKX_cEg.a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg.72CHiYFecyDvuUa43KKT6w';

        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['ECDH-ES+A128KW'], ['A128CBC-HS256'], ['DEF']);

        $loaded_compact_json = $this->getJWESerializerManager()->unserialize($maliciousJWE);
        $privateKey = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
        static::assertFalse($jweDecrypter->decryptUsingKey($loaded_compact_json, $privateKey, 0));
    }

    /**
     * @test
     */
    public function curveCheckNegativeP256AttackPt2(): void
    {
        // The malicious JWE contains a public key with order 2447
        $maliciousJWE = 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWE9YR1E5XzZRQ3ZCZzN1OHZDSS1VZEJ2SUNBRWNOTkJyZnFkN3RHN29RNCIsInkiOiJoUW9XTm90bk56S2x3aUNuZUprTElxRG5UTnc3SXNkQkM1M1ZVcVZqVkpjIiwiY3J2IjoiUC0yNTYifX0.UGb3hX3ePAvtFB9TCdWsNkFTv9QWxSr3MpYNiSBdW630uRXRBT3sxw.6VpU84oMob16DxOR98YTRw.y1UslvtkoWdl9HpugfP0rSAkTw1xhm_LbK1iRXzGdpYqNwIG5VU33UBpKAtKFBoA1Kk_sYtfnHYAvn-aes4FTg.UZPN8h7FcvA5MIOq-Pkj8A';
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['ECDH-ES+A128KW'], ['A128CBC-HS256'], ['DEF']);

        $loaded_compact_json = $this->getJWESerializerManager()->unserialize($maliciousJWE);
        $privateKey = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
        static::assertFalse($jweDecrypter->decryptUsingKey($loaded_compact_json, $privateKey, 0));
    }
}

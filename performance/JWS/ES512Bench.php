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

namespace Jose\Performance\JWS;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

/**
 * @Revs(4096)
 * @Groups({"JWS", "ECDSA", "ES512"})
 */
final class ES512Bench extends SignatureBench
{
    public function dataSignature(): array
    {
        return [
            [
                'algorithm' => 'ES512',
            ],
        ];
    }

    public function dataVerification(): array
    {
        return [
            [
                'input' => 'eyJhbGciOiJFUzUxMiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.AHWHIEWLWQl8n07gsrSx-UvwtUX1Clp-8QCJX20ifv3glXIJMRj9kiB8MlpKA_cpTaEROgf4apb5BYNqi3V4s7_CANg0hFc6_gJ-ECAjanlIVrXhFdJhDyIMhEkBkA3cq6HsWulJeZinP5CU-4_oNup--ir_PfQcui1jpboNwER6_XRG',
            ],
        ];
    }

    public function dataVerify(): array
    {
        return [
            [
                'signature' => 'AHWHIEWLWQl8n07gsrSx-UvwtUX1Clp-8QCJX20ifv3glXIJMRj9kiB8MlpKA_cpTaEROgf4apb5BYNqi3V4s7_CANg0hFc6_gJ-ECAjanlIVrXhFdJhDyIMhEkBkA3cq6HsWulJeZinP5CU-4_oNup--ir_PfQcui1jpboNwER6_XRG',
            ],
        ];
    }

    protected function getAlgorithm(): SignatureAlgorithm
    {
        return $this->getSignatureAlgorithmsManager()->get('ES512');
    }

    protected function getInput(): string
    {
        return 'eyJhbGciOiJFUzUxMiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';
    }

    protected function getPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'kid' => 'bilbo.baggins@hobbiton.example',
            'use' => 'sig',
            'crv' => 'P-521',
            'x' => 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt',
            'y' => 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1',
            'd' => 'AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt',
        ]);
    }

    protected function getPublicKey(): JWK
    {
        return $this->getPrivateKey()->toPublic();
    }
}

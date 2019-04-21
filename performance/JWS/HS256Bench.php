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
 * @Groups({"JWS", "hmac", "HS256"})
 */
final class HS256Bench extends SignatureBench
{
    public function dataSignature(): array
    {
        return [
            [
                'algorithm' => 'HS256',
            ],
        ];
    }

    public function dataVerification(): array
    {
        return [
            [
                'input' => 'eyJhbGciOiJIUzI1NiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20',
            ],
        ];
    }

    public function dataVerify(): array
    {
        return [
            [
                'signature' => 'bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20',
            ],
        ];
    }

    protected function getAlgorithm(): SignatureAlgorithm
    {
        return $this->getSignatureAlgorithmsManager()->get('HS256');
    }

    protected function getInput(): string
    {
        return 'eyJhbGciOiJIUzI1NiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';
    }

    protected function getPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);
    }

    protected function getPublicKey(): JWK
    {
        return $this->getPrivateKey();
    }
}

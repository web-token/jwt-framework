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
 * @Groups({"JWS", "ECDSA", "ES384"})
 */
final class ES384Bench extends SignatureBench
{
    public function dataSignature(): array
    {
        return [
            [
                'algorithm' => 'ES384',
            ],
        ];
    }

    public function dataVerification(): array
    {
        return [
            [
                'input' => 'eyJhbGciOiJFUzM4NCJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.KYD8GcuF5obFaHyjMHJu-v55pfcJdTw_0DSWU1achSeVqbJsGT0wjkGqfr839ZxB5x-g7hbAHKIFzwZanWq9cxoORKgUSQC6NRhtwM-Y_21aauWhB3Zz1FrNcnpKTAIq',
            ],
        ];
    }

    public function dataVerify(): array
    {
        return [
            [
                'signature' => 'KYD8GcuF5obFaHyjMHJu-v55pfcJdTw_0DSWU1achSeVqbJsGT0wjkGqfr839ZxB5x-g7hbAHKIFzwZanWq9cxoORKgUSQC6NRhtwM-Y_21aauWhB3Zz1FrNcnpKTAIq',
            ],
        ];
    }

    protected function getAlgorithm(): SignatureAlgorithm
    {
        return $this->getSignatureAlgorithmsManager()->get('ES384');
    }

    protected function getInput(): string
    {
        return 'eyJhbGciOiJFUzM4NCJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';
    }

    protected function getPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'kid' => 'peregrin.took@tuckborough.example',
            'use' => 'sig',
            'crv' => 'P-384',
            'x' => 'YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2',
            'y' => 'A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP',
            'd' => 'iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j',
        ]);
    }

    protected function getPublicKey(): JWK
    {
        return $this->getPrivateKey()->toPublic();
    }
}

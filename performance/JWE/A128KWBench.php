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

namespace Jose\Performance\JWE;

/**
 * @Revs(4096)
 * @Groups({"JWE", "KW", "A128KW"})
 */
final class A128KWBench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'A128KW', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A128KW', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A128KW', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A128KW', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A128KW', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A128KW', 'enc' => 'A256GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
        ];
    }

    protected function getAAD(): ?string
    {
        return 'A,B,C,D';
    }

    public function dataInputs(): array
    {
        return [
            ['input' => '{"ciphertext":"CGRKzNX-H6vQCdP3T_1ftzz6hFMMBWKSysDWPVmTG9TCviDXZh0u8k9WX42PiX-BrdRxxjIw9JMKgq3pxw8kQu4KyHeta4iio8OHr1Qjy24LPGRg9_Dv4Yt2i_ytHV_QbUX1Dg_YPMcca9G4BJA56927fvtGXA0ke0pjmPYceWSdZGxKO4MLLGJCHmi5xceIxhCy7QZnEfQOEv5bR2v_G0UDAi_eQM8","iv":"_PsWB_V0xIxq8ulL","tag":"RkfU2WT1DKGXFLgGZeCTnA","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"BX5Kx_b0rd5qUH0UqJe3h8Tu6bAPHLg-ZMFi7qHnEO7t46orRoW-xQ"}'],
        ];
    }

    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => ['keys' => [[
                    'kty' => 'oct',
                    'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
                ]]],
            ],
        ];
    }

    public function dataRecipientPublicKeys(): array
    {
        return [
            [
                'recipient_key' => [
                    'kty' => 'oct',
                    'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
                ],
            ],
        ];
    }
}

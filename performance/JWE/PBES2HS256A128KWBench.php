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
 * @Revs(1024)
 * @Groups({"JWE", "PBES2", "PBES2HS256A128KW"})
 */
final class PBES2HS256A128KWBench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'PBES2-HS256+A128KW', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'PBES2-HS256+A128KW', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'PBES2-HS256+A128KW', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'PBES2-HS256+A128KW', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'PBES2-HS256+A128KW', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'PBES2-HS256+A128KW', 'enc' => 'A256GCM'],
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
            ['input' => '{"ciphertext":"zDsBLNwrRjNHCEfiQ9exd62CC3ZF4XIXpW2pcVfME_ckTbCfrdCkMdhRLD6WZ0Ai-s2PF0esh536u56pJEWJkF5WKnCPCb4AowGleEBlh8yiR2i9KCLzIPUpyf3AH-ffKwIwEgYO33oGOJ55KBR6eYuFePhzxErgTTC4JA9KNxbRvoL-9TSqhOhYwYuMs9DoNmNTHPbh7AZiZyF-ZrZSZ7fEp4rMK8Y","iv":"B8c5oGxoX8I-7yKk","tag":"sh-wabbT17__NQqafuIKtQ","aad":"QSxCLEMsRA","protected":"eyJwMnMiOiJ2bG95RkN0MmhVc1hpQllDQVJlWGhHcjNYM3BOLWpldFFzVEFHc0doLUVBTThzbGFZMDNIUVNHQXVkaXFRV09pQndJSFdyTDdMcEFPMS1PQ0ttMEJEdyIsInAyYyI6NDA5NiwiYWxnIjoiUEJFUzItSFMyNTYrQTEyOEtXIiwiZW5jIjoiQTI1NkdDTSJ9","encrypted_key":"NYmhb9gVwG1AxG68L_jU4CuiuV7Z0UEg8vTpd0HVtkxCrF-oVzPmoQ"}'],
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

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
 * @Groups({"JWE", "GCMKW", "A256GCMKW"})
 */
final class A256GCMKWBench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'A256GCMKW', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A256GCMKW', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A256GCMKW', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A256GCMKW', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A256GCMKW', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'A256GCMKW', 'enc' => 'A256GCM'],
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
            ['input' => '{"ciphertext":"mdruX2DotBCFo0eYa0Hb1yOCdv2Dpg6tWBgTWUZ6Y9dLvZ2N-rJRjqgbyV3otZ_fpCurFdY5cX4Nk2G6A4tSw9Ixp5aQDaZgXasR_EhQjjiPSDjcSbQmpz0w8qGYmPX6OhH2G0iKtp2aFjgHK4tHvTl4abu72mqmJgoOTzYCiyin0BujbTB33v1TsM-0uPWdY9LziVkf4z2DV81ehj9iHbj7_cq9ABk","iv":"aeHHwTKalLxq-s_2","tag":"9lF1kYUWyvkXFT-r9hwsoA","aad":"QSxCLEMsRA","protected":"eyJpdiI6IjdHVEJDcXBjQktORnktN20iLCJ0YWciOiJGV29vY1dESDhSb1NfZVVQREQ1UVlBIiwiYWxnIjoiQTI1NkdDTUtXIiwiZW5jIjoiQTI1NkdDTSJ9","encrypted_key":"3nTasDHjqnzYhjJRwcxpCfs_lnrrT2YUzI8EdnbVI4I"}'],
        ];
    }

    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => ['keys' => [[
                    'kty' => 'oct',
                    'k' => 'OgUyABAPIkI-zFg3doqsv_GH-4GTGOu3HGnuG9wdxCo',
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
                    'k' => 'OgUyABAPIkI-zFg3doqsv_GH-4GTGOu3HGnuG9wdxCo',
                ],
            ],
        ];
    }
}

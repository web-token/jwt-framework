<?php

declare(strict_types=1);

namespace Jose\Performance\JWE;

use Override;
use PhpBench\Benchmark\Metadata\Annotations\Groups;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

/**
 * @Revs(4096)
 * @Groups({"JWE", "KW", "A256KW"})
 */
final class A256KWBench extends EncryptionBench
{
    #[Override]
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => [
                    'alg' => 'A256KW',
                    'enc' => 'A128CBC-HS256',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A256KW',
                    'enc' => 'A192CBC-HS384',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A256KW',
                    'enc' => 'A256CBC-HS512',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A256KW',
                    'enc' => 'A128GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A256KW',
                    'enc' => 'A192GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A256KW',
                    'enc' => 'A256GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
        ];
    }

    public function dataInputs(): array
    {
        return [
            [
                'input' => '{"ciphertext":"Js4OCNZs2s0En9-JTEzHntCLjUYHwd9mgEuMgTlQQCACrTcwctobqEyEXIEnHhFqQb6FDi7z6gXrY4pJdMnZAbY-DF2KlzPewPJdPCtncGMJ6Q-tJ7_aNoBQbR9yFpcdPqzZKG5l_g3JjI5n2z1pP2T3-tvwFN6UJvUBy-gQJgkosXlEXEcDcpGcGl41wLUwv-uVg-T6_i52_MDHg4CqST_5qugu6_Y","iv":"nqT3ZOuxL5i-6zFa","tag":"6XRD6atZ3kX1AXMFw9Np5g","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"L7ZhHtUPPSyrxyE36QFyt7dlb6GSmPZSoP-1HUkAe0d8PDKIXLwjAw"}',
            ],
        ];
    }

    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => [
                    'keys' => [[
                        'kty' => 'oct',
                        'k' => 'OgUyABAPIkI-zFg3doqsv_GH-4GTGOu3HGnuG9wdxCo',
                    ]],
                ],
            ],
        ];
    }

    #[Override]
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

    #[Override]
    protected function getAAD(): ?string
    {
        return 'A,B,C,D';
    }
}

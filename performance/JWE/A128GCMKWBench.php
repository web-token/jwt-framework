<?php

declare(strict_types=1);

namespace Jose\Performance\JWE;

use Override;
use PhpBench\Benchmark\Metadata\Annotations\Groups;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

/**
 * @Revs(4096)
 * @Groups({"JWE", "GCMKW", "A128GCMKW"})
 */
final class A128GCMKWBench extends EncryptionBench
{
    #[Override]
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => [
                    'alg' => 'A128GCMKW',
                    'enc' => 'A128CBC-HS256',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A128GCMKW',
                    'enc' => 'A192CBC-HS384',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A128GCMKW',
                    'enc' => 'A256CBC-HS512',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A128GCMKW',
                    'enc' => 'A128GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A128GCMKW',
                    'enc' => 'A192GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A128GCMKW',
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
                'input' => '{"ciphertext":"crbOdBQqlc8WJZ9ZTb42xYoy2i5_KBoSOeJSg_6aeG0V1gxfVqe_AIkS9Nv8Vmil785R909ntom9Fo1GPZnt9mv-UfBeON7V1shRYjtOog6KouOvnA0YROvNr32AhE_tVrxzFyFVLRwJE0kfXvG29GhwTxhz2ugCqNZdIPJL5awM5BXosxlSiZRsHRMYSsULvfOTPqb2JkWbT1Z7bgCmm885-U01uaA","iv":"RUYx0bI8ywiHbgOI","tag":"rRPgmpp8UvOOhT_SVOGaIg","aad":"QSxCLEMsRA","protected":"eyJpdiI6Ikd4V1R2ZG96Zk1KZUcxQmMiLCJ0YWciOiJXYlM1Nk93NnUwUl9oZDZJQzZaZU9RIiwiYWxnIjoiQTEyOEdDTUtXIiwiZW5jIjoiQTI1NkdDTSJ9","encrypted_key":"r3zhEPolUXhQ0kHvg-wyxOYDDilfL4WJWAlfxlwIIm4"}',
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
                        'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
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
                    'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
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

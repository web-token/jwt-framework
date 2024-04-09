<?php

declare(strict_types=1);

namespace Jose\Performance\JWE;

use Override;
use PhpBench\Benchmark\Metadata\Annotations\Groups;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

/**
 * @Revs(4096)
 * @Groups({"JWE", "GCMKW", "A192GCMKW"})
 */
final class A192GCMKWBench extends EncryptionBench
{
    #[Override]
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => [
                    'alg' => 'A192GCMKW',
                    'enc' => 'A128CBC-HS256',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A192GCMKW',
                    'enc' => 'A192CBC-HS384',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A192GCMKW',
                    'enc' => 'A256CBC-HS512',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A192GCMKW',
                    'enc' => 'A128GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A192GCMKW',
                    'enc' => 'A192GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'A192GCMKW',
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
                'input' => '{"ciphertext":"8-zEiA24sXMcmZl33nvu7sdP5gIupkNAcWkg2qE5bfRdReOiocGlYOr0GPj9SjJDEJUCdbMbsn3qx6cFkZaPmV_G5w7dNfX8ALhLVhSkbypW2C2TGGxaEEAnGJgjwBhi-wDd-k1bAU0htRszUi_RsY3sfb5ssDJZQkyslxtubVSTqWkpH0tuotxQxac2mDHrWAp0VYnpGSJSKPy3q3UGlxY812zaEOc","iv":"dCoOw5_olUz_kCjN","tag":"TGiZO1fqeb0pfdTlc5VYJQ","aad":"QSxCLEMsRA","protected":"eyJpdiI6IkNST0xGWS1CbVVUSmoxQlIiLCJ0YWciOiJVVTFtdExPcldCeFRaYW5OM2FKZWpBIiwiYWxnIjoiQTE5MkdDTUtXIiwiZW5jIjoiQTI1NkdDTSJ9","encrypted_key":"Z8_qLErKWsleFJuq1jBXWcJovvHUdhvJfZa9ecDbLJw"}',
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
                        'k' => 'KuFiR-n2ngkDNZfBXWS6cCGXrYonVUiH',
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
                    'k' => 'KuFiR-n2ngkDNZfBXWS6cCGXrYonVUiH',
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

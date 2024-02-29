<?php

declare(strict_types=1);

namespace Jose\Performance\JWE;

use Override;
use PhpBench\Benchmark\Metadata\Annotations\Groups;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

/**
 * @Revs(1024)
 * @Groups({"JWE", "PBES2", "PBES2HS384A192KW"})
 */
final class PBES2HS384A192KWBench extends EncryptionBench
{
    #[Override]
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => [
                    'alg' => 'PBES2-HS384+A192KW',
                    'enc' => 'A128CBC-HS256',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'PBES2-HS384+A192KW',
                    'enc' => 'A192CBC-HS384',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'PBES2-HS384+A192KW',
                    'enc' => 'A256CBC-HS512',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'PBES2-HS384+A192KW',
                    'enc' => 'A128GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'PBES2-HS384+A192KW',
                    'enc' => 'A192GCM',
                ],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => [
                    'alg' => 'PBES2-HS384+A192KW',
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
                'input' => '{"ciphertext":"eG8lMbMf784k-Vxb9Da6jci9O6GxT2aH88RhoKkmTslRrlsP6VCPTeQVj7-J0SPfuRYid9tFIft2taBGUKcCVO_Sx7hsQUUu0dvwo1L5F5biOzg0l1EdsSgiDBYAG5-vgHTq2_1SOeqtJ-m9Yk1LV_-SwFEnHd8il02bWq20l7LazfVy4pU1NCdS3Y2qwYET7RZeNetxR09LKf4XNY5GLy-vtDzou3w","iv":"3I-Tv6gEXNbjB48h","tag":"RwNOwY8c_cTHmwyIBckSUQ","aad":"QSxCLEMsRA","protected":"eyJwMnMiOiJaZThzQnUzdnd6Y0ZmVlJXOXhXSVdKN2tGYWxvSS1OUFZZUW85NW9kemF0VFAwRzN0RkVZVGVWVWFqelJzV2xXTGoyWmJXWnpHV2pOQzBsVDRQMVdJdyIsInAyYyI6NDA5NiwiYWxnIjoiUEJFUzItSFMzODQrQTE5MktXIiwiZW5jIjoiQTI1NkdDTSJ9","encrypted_key":"eGor6-Vqm9qVKpYHTmkZtQuUFeYSdkMmM9nx8_pq_dtm4NVlaXfaZg"}',
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

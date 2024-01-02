<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use function array_key_exists;

final class AlgorithmCollector implements Collector
{
    public function __construct(
        private readonly AlgorithmManagerFactory $algorithmManagerFactory
    ) {
    }

    /**
     * @param array<string, mixed> $data
     */
    public function collect(array &$data, Request $request, Response $response, ?Throwable $exception = null): void
    {
        $algorithms = $this->algorithmManagerFactory->all();
        $data['algorithm'] = [
            'messages' => $this->getAlgorithmMessages(),
            'algorithms' => [],
        ];
        $signatureAlgorithms = 0;
        $macAlgorithms = 0;
        $keyEncryptionAlgorithms = 0;
        $contentEncryptionAlgorithms = 0;
        foreach ($algorithms as $alias => $algorithm) {
            $type = $this->getAlgorithmType(
                $algorithm,
                $signatureAlgorithms,
                $macAlgorithms,
                $keyEncryptionAlgorithms,
                $contentEncryptionAlgorithms
            );
            if (! array_key_exists($type, $data['algorithm']['algorithms'])) {
                $data['algorithm']['algorithms'][$type] = [];
            }
            $data['algorithm']['algorithms'][$type][$alias] = [
                'name' => $algorithm->name(),
            ];
        }

        $data['algorithm']['types'] = [
            'signature' => $signatureAlgorithms,
            'mac' => $macAlgorithms,
            'key_encryption' => $keyEncryptionAlgorithms,
            'content_encryption' => $contentEncryptionAlgorithms,
        ];
    }

    private function getAlgorithmType(
        Algorithm $algorithm,
        int &$signatureAlgorithms,
        int &$macAlgorithms,
        int &$keyEncryptionAlgorithms,
        int &$contentEncryptionAlgorithms
    ): string {
        switch (true) {
            case $algorithm instanceof SignatureAlgorithm:
                $signatureAlgorithms++;

                return 'Signature';

            case $algorithm instanceof MacAlgorithm:
                $macAlgorithms++;

                return 'MAC';

            case $algorithm instanceof KeyEncryptionAlgorithm:
                $keyEncryptionAlgorithms++;

                return 'Key Encryption';

            case $algorithm instanceof ContentEncryptionAlgorithm:
                $contentEncryptionAlgorithms++;

                return 'Content Encryption';

            default:
                return 'Unknown';
        }
    }

    /**
     * @return array<string, array<string, string>>
     */
    private function getAlgorithmMessages(): array
    {
        return [
            'none' => [
                'severity' => 'severity-low',
                'message' => 'This algorithm is not secured. Please use with caution.',
            ],
            'HS256/64' => [
                'severity' => 'severity-low',
                'message' => 'Experimental. Please use for testing purpose only.',
            ],
            'RS1' => [
                'severity' => 'severity-high',
                'message' => 'Experimental. Please use for testing purpose only. SHA-1 hashing function is not recommended.',
            ],
            'RS256' => [
                'severity' => 'severity-medium',
                'message' => 'RSAES-PKCS1-v1_5 based algorithms are not recommended.',
            ],
            'RS384' => [
                'severity' => 'severity-medium',
                'message' => 'RSAES-PKCS1-v1_5 based algorithms are not recommended.',
            ],
            'RS512' => [
                'severity' => 'severity-medium',
                'message' => 'RSAES-PKCS1-v1_5 based algorithms are not recommended.',
            ],
            'HS1' => [
                'severity' => 'severity-high',
                'message' => 'This algorithm has known vulnerabilities. See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-17">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-17</a>. SHA-1 hashing function is not recommended.',
            ],
            'A128CTR' => [
                'severity' => 'severity-high',
                'message' => 'This algorithm is prohibited. For compatibility with old application only. See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11</a>.',
            ],
            'A192CTR' => [
                'severity' => 'severity-high',
                'message' => 'This algorithm is prohibited. For compatibility with old application only. See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11</a>.',
            ],
            'A256CTR' => [
                'severity' => 'severity-high',
                'message' => 'This algorithm is prohibited. For compatibility with old application only. See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11</a>.',
            ],
            'A128CBC' => [
                'severity' => 'severity-high',
                'message' => 'This algorithm is prohibited. For compatibility with old application only. See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11</a>.',
            ],
            'A192CBC' => [
                'severity' => 'severity-high',
                'message' => 'This algorithm is prohibited. For compatibility with old application only. See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11</a>.',
            ],
            'A256CBC' => [
                'severity' => 'severity-high',
                'message' => 'This algorithm is prohibited. For compatibility with old application only. See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-11</a>.',
            ],
            'chacha20-poly1305' => [
                'severity' => 'severity-low',
                'message' => 'Experimental. Please use for testing purpose only.',
            ],
            'RSA-OAEP-384' => [
                'severity' => 'severity-low',
                'message' => 'Experimental. Please use for testing purpose only.',
            ],
            'RSA-OAEP-512' => [
                'severity' => 'severity-low',
                'message' => 'Experimental. Please use for testing purpose only.',
            ],
            'A128CCM-16-64' => [
                'severity' => 'severity-low',
                'message' => 'Experimental and subject to changes. Please use for testing purpose only.',
            ],
            'A256CCM-16-64' => [
                'severity' => 'severity-low',
                'message' => 'Experimental and subject to changes. Please use for testing purpose only.',
            ],
            'A128CCM-64-64' => [
                'severity' => 'severity-low',
                'message' => 'Experimental and subject to changes. Please use for testing purpose only.',
            ],
            'A256CCM-64-64' => [
                'severity' => 'severity-low',
                'message' => 'Experimental and subject to changes. Please use for testing purpose only.',
            ],
            'A128CCM-16-128' => [
                'severity' => 'severity-low',
                'message' => 'Experimental and subject to changes. Please use for testing purpose only.',
            ],
            'A256CCM-16-128' => [
                'severity' => 'severity-low',
                'message' => 'Experimental and subject to changes. Please use for testing purpose only.',
            ],
            'A128CCM-64-128' => [
                'severity' => 'severity-low',
                'message' => 'Experimental and subject to changes. Please use for testing purpose only.',
            ],
            'A256CCM-64-128' => [
                'severity' => 'severity-low',
                'message' => 'Experimental and subject to changes. Please use for testing purpose only.',
            ],
            'RSA1_5' => [
                'severity' => 'severity-high',
                'message' => 'This algorithm is not secured (known attacks). See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-5">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-5</a>.',
            ],
        ];
    }
}

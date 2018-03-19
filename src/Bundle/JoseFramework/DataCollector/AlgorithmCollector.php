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

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AlgorithmCollector implements Collector
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * AlgorithmCollector constructor.
     *
     * @param AlgorithmManagerFactory $algorithmManagerFactory
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(array &$data, Request $request, Response $response, \Exception $exception = null)
    {
        $algorithms = $this->algorithmManagerFactory->all();
        $data['algorithm'] = [
            'messages'   => $this->getAlgorithmMessages(),
            'algorithms' => [],
        ];
        $signatureAlgorithms = 0;
        $keyEncryptionAlgorithms = 0;
        $contentEncryptionAlgorithms = 0;
        foreach ($algorithms as $alias => $algorithm) {
            $type = $this->getAlgorithmType($algorithm, $signatureAlgorithms, $keyEncryptionAlgorithms, $contentEncryptionAlgorithms);
            if (!array_key_exists($type, $data['algorithm']['algorithms'])) {
                $data['algorithm']['algorithms'][$type] = [];
            }
            $data['algorithm']['algorithms'][$type][$alias] = [
                'name' => $algorithm->name(),
            ];
        }

        $data['algorithm']['types'] = [
            'signature'          => $signatureAlgorithms,
            'key_encryption'     => $keyEncryptionAlgorithms,
            'content_encryption' => $contentEncryptionAlgorithms,
        ];
    }

    /**
     * @param Algorithm $algorithm
     * @param int       $signatureAlgorithms
     * @param int       $keyEncryptionAlgorithms
     * @param int       $contentEncryptionAlgorithms
     *
     * @return string
     */
    private function getAlgorithmType(Algorithm $algorithm, int &$signatureAlgorithms, int &$keyEncryptionAlgorithms, int &$contentEncryptionAlgorithms): string
    {
        switch (true) {
            case $algorithm instanceof SignatureAlgorithm:
                $signatureAlgorithms++;

                return 'Signature';
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
     * @return array
     */
    private function getAlgorithmMessages(): array
    {
        return [
            'none' => [
                'severity' => 'severity-low',
                'message'  => 'This algorithm is not secured. Please use with caution.',
            ],
            'RSA1_5' => [
                'severity' => 'severity-high',
                'message'  => 'This algorithm is not secured (known attacks). See <a target="_blank" href="https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-5">https://tools.ietf.org/html/draft-irtf-cfrg-webcrypto-algorithms-00#section-5</a>.',
            ],
            'ECDH-ES' => [
                'severity' => 'severity-medium',
                'message'  => 'This algorithm is very slow when used with curves P-256, P-384, P-521.',
            ],
            'ECDH-ES+A128KW' => [
                'severity' => 'severity-medium',
                'message'  => 'This algorithm is very slow when used with curves P-256, P-384, P-521.',
            ],
            'ECDH-ES+A192KW' => [
                'severity' => 'severity-medium',
                'message'  => 'This algorithm is very slow when used with curves P-256, P-384, P-521.',
            ],
            'ECDH-ES+A256KW' => [
                'severity' => 'severity-medium',
                'message'  => 'This algorithm is very slow when used with curves P-256, P-384, P-521.',
            ],
        ];
    }
}

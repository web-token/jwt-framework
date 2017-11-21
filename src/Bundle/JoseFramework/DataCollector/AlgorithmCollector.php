<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
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

final class AlgorithmCollector implements Collector
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
        $this->collectSupportedAlgorithms($data);
    }

    public function name(): string
    {
        return 'algorithm';
    }

    /**
     * @param array $data
     *
     * @return array
     */
    public function getAlgorithmDetails(array $data): array
    {
        return $data['algorithms'];
    }

    /**
     * @param array $data
     *
     * @return int
     */
    public function countSignatureAlgorithms(array $data): int
    {
        return $data['types']['signature'];
    }

    /**
     * @param array $data
     *
     * @return int
     */
    public function countKeyEncryptionAlgorithms(array $data): int
    {
        return $data['types']['key_encryption'];
    }

    /**
     * @param array $data
     *
     * @return int
     */
    public function countContentEncryptionAlgorithms(array $data): int
    {
        return $data['types']['content_encryption'];
    }

    private function collectSupportedAlgorithms(array &$data)
    {
        $algorithms = $this->algorithmManagerFactory->all();
        $data['algorithms'] = [];
        $signatureAlgorithms = 0;
        $keyEncryptionAlgorithms = 0;
        $contentEncryptionAlgorithms = 0;
        foreach ($algorithms as $alias => $algorithm) {
            $type = $this->getAlgorithmType($algorithm, $signatureAlgorithms, $keyEncryptionAlgorithms, $contentEncryptionAlgorithms);
            if (!array_key_exists($type, $data['algorithms'])) {
                $data['algorithms'][$type] = [];
            }
            $data['algorithms'][$type][$alias] = [
                'name' => $algorithm->name(),
            ];
        }

        $data['types'] = [
            'signature' => $signatureAlgorithms,
            'key_encryption' => $keyEncryptionAlgorithms,
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
}

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

use Jose\Component\Core\AlgorithmInterface;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\Signature\Algorithm\SignatureAlgorithmInterface;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

final class JoseCollector extends DataCollector
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var CompressionMethodManagerFactory|null
     */
    private $compressionMethodManagerFactory;

    /**
     * @var JWSSerializerManagerFactory|null
     */
    private $jwsSerializerManagerFactory;

    /**
     * @var JWESerializerManagerFactory|null
     */
    private $jweSerializerManagerFactory;

    /**
     * JoseCollector constructor.
     *
     * @param AlgorithmManagerFactory              $algorithmManagerFactory
     * @param CompressionMethodManagerFactory|null $compressionMethodManagerFactory
     * @param JWSSerializerManagerFactory|null     $jwsSerializerManagerFactory
     * @param JWESerializerManagerFactory|null     $jweSerializerManagerFactory
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, ?CompressionMethodManagerFactory $compressionMethodManagerFactory = null, ?JWSSerializerManagerFactory $jwsSerializerManagerFactory = null, ?JWESerializerManagerFactory $jweSerializerManagerFactory = null)
    {
        $this->data = [];
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
        $this->jwsSerializerManagerFactory = $jwsSerializerManagerFactory;
        $this->jweSerializerManagerFactory = $jweSerializerManagerFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(Request $request, Response $response, \Exception $exception = null)
    {
        $this->collectSupportedAlgorithms();
        $this->collectSupportedCompressionMethods();
        $this->collectSupportedJWSSerializations();
        $this->collectSupportedJWESerializations();
    }

    /**
     * @return array
     */
    public function getAlgorithmDetails(): array
    {
        return $this->data['algorithms'];
    }

    /**
     * @return int
     */
    public function countSignatureAlgorithms(): int
    {
        return $this->data['types']['signature'];
    }

    /**
     * @return int
     */
    public function countKeyEncryptionAlgorithms(): int
    {
        return $this->data['types']['key_encryption'];
    }

    /**
     * @return int
     */
    public function countContentEncryptionAlgorithms(): int
    {
        return $this->data['types']['content_encryption'];
    }

    /**
     * @return array
     */
    public function getCompressionMethodDetails(): array
    {
        return $this->data['compression_methods'];
    }

    /**
     * @return array
     */
    public function getJWSSerializationDetails(): array
    {
        return $this->data['jws_serialization'];
    }

    /**
     * @return array
     */
    public function getJWESerializationDetails(): array
    {
        return $this->data['jwe_serialization'];
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'jose_collector';
    }

    private function collectSupportedAlgorithms()
    {
        $algorithms = $this->algorithmManagerFactory->all();
        $this->data['algorithms'] = [];
        $signatureAlgorithms = 0;
        $keyEncryptionAlgorithms = 0;
        $contentEncryptionAlgorithms = 0;
        foreach ($algorithms as $alias => $algorithm) {
            $type = $this->getAlgorithmType($algorithm, $signatureAlgorithms, $keyEncryptionAlgorithms, $contentEncryptionAlgorithms);
            if (!array_key_exists($type, $this->data['algorithms'])) {
                $this->data['algorithms'][$type] = [];
            }
            $this->data['algorithms'][$type][$alias] = [
                'name' => $algorithm->name(),
            ];
        }

        $this->data['types'] = [
            'signature' => $signatureAlgorithms,
            'key_encryption' => $keyEncryptionAlgorithms,
            'content_encryption' => $contentEncryptionAlgorithms,
        ];
    }

    /**
     * @param AlgorithmInterface $algorithm
     * @param int                $signatureAlgorithms
     * @param int                $keyEncryptionAlgorithms
     * @param int                $contentEncryptionAlgorithms
     *
     * @return string
     */
    private function getAlgorithmType(AlgorithmInterface $algorithm, int &$signatureAlgorithms, int &$keyEncryptionAlgorithms, int &$contentEncryptionAlgorithms): string
    {
        switch (true) {
            case $algorithm instanceof SignatureAlgorithmInterface:
                $signatureAlgorithms++;

                return 'Signature';
            case $algorithm instanceof KeyEncryptionAlgorithmInterface:
                $keyEncryptionAlgorithms++;

                return 'Key Encryption';
            case $algorithm instanceof ContentEncryptionAlgorithmInterface:
                $contentEncryptionAlgorithms++;

                return 'Content Encryption';
            default:
                return 'Unknown';
        }
    }

    private function collectSupportedCompressionMethods()
    {
        $this->data['compression_methods'] = [];
        if (null === $this->compressionMethodManagerFactory) {
            return;
        }
        $compressionMethods = $this->compressionMethodManagerFactory->all();
        foreach ($compressionMethods as $alias => $compressionMethod) {
            $this->data['compression_methods'][$alias] = $compressionMethod->name();
        }
    }

    private function collectSupportedJWSSerializations()
    {
        $this->data['jws_serialization'] = [];
        if (null === $this->jwsSerializerManagerFactory) {
            return;
        }
        $serializers = $this->jwsSerializerManagerFactory->all();
        foreach ($serializers as $serializer) {
            $this->data['jws_serialization'][$serializer->name()] = $serializer->displayName();
        }
    }

    private function collectSupportedJWESerializations()
    {
        $this->data['jwe_serialization'] = [];
        if (null === $this->jweSerializerManagerFactory) {
            return;
        }
        $serializers = $this->jweSerializerManagerFactory->all();
        foreach ($serializers as $serializer) {
            $this->data['jwe_serialization'][$serializer->name()] = $serializer->displayName();
        }
    }
}

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

use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class JWECollector implements Collector
{
    /**
     * @var JWESerializerManagerFactory|null
     */
    private $jweSerializerManagerFactory;

    /**
     * @var CompressionMethodManagerFactory|null
     */
    private $compressionMethodManagerFactory;

    /**
     * JWECollector constructor.
     *
     * @param CompressionMethodManagerFactory|null $compressionMethodManagerFactory
     * @param JWESerializerManagerFactory|null     $jweSerializerManagerFactory
     */
    public function __construct(?CompressionMethodManagerFactory $compressionMethodManagerFactory = null, ?JWESerializerManagerFactory $jweSerializerManagerFactory = null)
    {
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
        $this->jweSerializerManagerFactory = $jweSerializerManagerFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(array &$data, Request $request, Response $response, \Exception $exception = null)
    {
        $this->collectSupportedCompressionMethods($data);
        $this->collectSupportedJWESerializations($data);
        $this->collectSupportedJWEBuilders($data);
        $this->collectSupportedJWEDecrypters($data);
    }

    /**
     * @param array $data
     */
    private function collectSupportedCompressionMethods(array &$data)
    {
        $data['jwe']['compression_methods'] = [];
        if (null === $this->compressionMethodManagerFactory) {
            return;
        }
        $compressionMethods = $this->compressionMethodManagerFactory->all();
        foreach ($compressionMethods as $alias => $compressionMethod) {
            $data['jwe']['compression_methods'][$alias] = $compressionMethod->name();
        }
    }

    /**
     * @param array $data
     */
    private function collectSupportedJWESerializations(array &$data)
    {
        $data['jwe']['jwe_serialization'] = [];
        if (null === $this->jweSerializerManagerFactory) {
            return;
        }
        $serializers = $this->jweSerializerManagerFactory->all();
        foreach ($serializers as $serializer) {
            $data['jwe']['jwe_serialization'][$serializer->name()] = $serializer->displayName();
        }
    }

    /**
     * @param array $data
     */
    private function collectSupportedJWEBuilders(array &$data)
    {
        $data['jwe']['jwe_builders'] = [];
        foreach ($this->jweBuilders as $id => $jweBuilder) {
            $data['jwe']['jwe_builders'][$id] = [
                'key_encryption_algorithms'     => $jweBuilder->getKeyEncryptionAlgorithmManager()->list(),
                'content_encryption_algorithms' => $jweBuilder->getContentEncryptionAlgorithmManager()->list(),
                'compression_methods'           => $jweBuilder->getCompressionMethodManager()->list(),
            ];
        }
    }

    /**
     * @param array $data
     */
    private function collectSupportedJWEDecrypters(array &$data)
    {
        $data['jwe']['jwe_decrypters'] = [];
        foreach ($this->jweDecrypters as $id => $jweDecrypter) {
            $data['jwe']['jwe_decrypters'][$id] = [
                'key_encryption_algorithms'     => $jweDecrypter->getKeyEncryptionAlgorithmManager()->list(),
                'content_encryption_algorithms' => $jweDecrypter->getContentEncryptionAlgorithmManager()->list(),
                'compression_methods'           => $jweDecrypter->getCompressionMethodManager()->list(),
            ];
        }
    }

    /**
     * @var JWEBuilder[]
     */
    private $jweBuilders = [];

    /**
     * @param string     $id
     * @param JWEBuilder $jweBuilder
     */
    public function addJWEBuilder(string $id, JWEBuilder $jweBuilder)
    {
        $this->jweBuilders[$id] = $jweBuilder;
    }

    /**
     * @var JWEDecrypter[]
     */
    private $jweDecrypters = [];

    /**
     * @param string       $id
     * @param JWEDecrypter $jweDecrypter
     */
    public function addJWEDecrypter(string $id, JWEDecrypter $jweDecrypter)
    {
        $this->jweDecrypters[$id] = $jweDecrypter;
    }
}

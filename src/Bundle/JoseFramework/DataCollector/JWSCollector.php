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

use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class JWSCollector implements Collector
{
    /**
     * @var JWSSerializerManagerFactory|null
     */
    private $jwsSerializerManagerFactory;

    /**
     * JWSCollector constructor.
     *
     * @param JWSSerializerManagerFactory|null $jwsSerializerManagerFactory
     */
    public function __construct(?JWSSerializerManagerFactory $jwsSerializerManagerFactory = null)
    {
        $this->jwsSerializerManagerFactory = $jwsSerializerManagerFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(array &$data, Request $request, Response $response, \Exception $exception = null)
    {
        $this->collectSupportedJWSSerializations($data);
        $this->collectSupportedJWSBuilders($data);
        $this->collectSupportedJWSVerifiers($data);
    }

    /**
     * @param array $data
     */
    private function collectSupportedJWSSerializations(array &$data)
    {
        $data['jws']['jws_serialization'] = [];
        if (null === $this->jwsSerializerManagerFactory) {
            return;
        }
        $serializers = $this->jwsSerializerManagerFactory->all();
        foreach ($serializers as $serializer) {
            $data['jws']['jws_serialization'][$serializer->name()] = $serializer->displayName();
        }
    }

    /**
     * @param array $data
     */
    private function collectSupportedJWSBuilders(array &$data)
    {
        $data['jws']['jws_builders'] = [];
        foreach ($this->jwsBuilders as $id => $jwsBuilder) {
            $data['jws']['jws_builders'][$id] = [
                'signature_algorithms' => $jwsBuilder->getSignatureAlgorithmManager()->list(),
            ];
        }
    }

    /**
     * @param array $data
     */
    private function collectSupportedJWSVerifiers(array &$data)
    {
        $data['jws']['jws_verifiers'] = [];
        foreach ($this->jwsVerifiers as $id => $jwsVerifier) {
            $data['jws']['jws_verifiers'][$id] = [
                'signature_algorithms' => $jwsVerifier->getSignatureAlgorithmManager()->list(),
            ];
        }
    }

    /**
     * @var JWSBuilder[]
     */
    private $jwsBuilders = [];

    /**
     * @param string     $id
     * @param JWSBuilder $jwsBuilder
     */
    public function addJWSBuilder(string $id, JWSBuilder $jwsBuilder)
    {
        $this->jwsBuilders[$id] = $jwsBuilder;
    }

    /**
     * @var JWSVerifier[]
     */
    private $jwsVerifiers = [];

    /**
     * @param string      $id
     * @param JWSVerifier $jwsVerifier
     */
    public function addJWSVerifier(string $id, JWSVerifier $jwsVerifier)
    {
        $this->jwsVerifiers[$id] = $jwsVerifier;
    }
}

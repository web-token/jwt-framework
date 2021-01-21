<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Bundle\JoseFramework\Event\JWSBuiltFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSBuiltSuccessEvent;
use Jose\Bundle\JoseFramework\Event\JWSVerificationFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSVerificationSuccessEvent;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Throwable;

class JWSCollector implements Collector, EventSubscriberInterface
{
    /**
     * @var null|JWSSerializerManagerFactory
     */
    private $jwsSerializerManagerFactory;

    /**
     * @var JWSBuilder[]
     */
    private $jwsBuilders = [];

    /**
     * @var JWSVerifier[]
     */
    private $jwsVerifiers = [];

    /**
     * @var JWSLoader[]
     */
    private $jwsLoaders = [];

    /**
     * @var array
     */
    private $jwsVerificationSuccesses = [];

    /**
     * @var array
     */
    private $jwsVerificationFailures = [];

    /**
     * @var array
     */
    private $jwsBuiltSuccesses = [];

    /**
     * @var array
     */
    private $jwsBuiltFailures = [];

    public function __construct(?JWSSerializerManagerFactory $jwsSerializerManagerFactory = null)
    {
        $this->jwsSerializerManagerFactory = $jwsSerializerManagerFactory;
    }

    public function collect(array &$data, Request $request, Response $response, ?Throwable $exception = null): void
    {
        $this->collectSupportedJWSSerializations($data);
        $this->collectSupportedJWSBuilders($data);
        $this->collectSupportedJWSVerifiers($data);
        $this->collectSupportedJWSLoaders($data);
        $this->collectEvents($data);
    }

    public function addJWSBuilder(string $id, JWSBuilder $jwsBuilder): void
    {
        $this->jwsBuilders[$id] = $jwsBuilder;
    }

    public function addJWSVerifier(string $id, JWSVerifier $jwsVerifier): void
    {
        $this->jwsVerifiers[$id] = $jwsVerifier;
    }

    public function addJWSLoader(string $id, JWSLoader $jwsLoader): void
    {
        $this->jwsLoaders[$id] = $jwsLoader;
    }

    public static function getSubscribedEvents()
    {
        return [
            JWSVerificationSuccessEvent::class => ['catchJwsVerificationSuccess'],
            JWSVerificationFailureEvent::class => ['catchJwsVerificationFailure'],
            JWSBuiltSuccessEvent::class => ['catchJwsBuiltSuccess'],
            JWSBuiltFailureEvent::class => ['catchJwsBuiltFailure'],
        ];
    }

    public function catchJwsVerificationSuccess(JWSVerificationSuccessEvent $event): void
    {
        $cloner = new VarCloner();
        $this->jwsVerificationSuccesses[] = $cloner->cloneVar($event);
    }

    public function catchJwsVerificationFailure(JWSVerificationFailureEvent $event): void
    {
        $cloner = new VarCloner();
        $this->jwsVerificationFailures[] = $cloner->cloneVar($event);
    }

    public function catchJwsBuiltSuccess(JWSBuiltSuccessEvent $event): void
    {
        $cloner = new VarCloner();
        $this->jwsBuiltSuccesses[] = $cloner->cloneVar($event);
    }

    public function catchJwsBuiltFailure(JWSBuiltFailureEvent $event): void
    {
        $cloner = new VarCloner();
        $this->jwsBuiltFailures[] = $cloner->cloneVar($event);
    }

    private function collectSupportedJWSSerializations(array &$data): void
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

    private function collectSupportedJWSBuilders(array &$data): void
    {
        $data['jws']['jws_builders'] = [];
        foreach ($this->jwsBuilders as $id => $jwsBuilder) {
            $data['jws']['jws_builders'][$id] = [
                'signature_algorithms' => $jwsBuilder->getSignatureAlgorithmManager()->list(),
            ];
        }
    }

    private function collectSupportedJWSVerifiers(array &$data): void
    {
        $data['jws']['jws_verifiers'] = [];
        foreach ($this->jwsVerifiers as $id => $jwsVerifier) {
            $data['jws']['jws_verifiers'][$id] = [
                'signature_algorithms' => $jwsVerifier->getSignatureAlgorithmManager()->list(),
            ];
        }
    }

    private function collectSupportedJWSLoaders(array &$data): void
    {
        $data['jws']['jws_loaders'] = [];
        foreach ($this->jwsLoaders as $id => $jwsLoader) {
            $data['jws']['jws_loaders'][$id] = [
                'serializers' => $jwsLoader->getSerializerManager()->list(),
                'signature_algorithms' => $jwsLoader->getJwsVerifier()->getSignatureAlgorithmManager()->list(),
            ];
        }
    }

    private function collectEvents(array &$data): void
    {
        $data['jws']['events'] = [
            'verification_success' => $this->jwsVerificationSuccesses,
            'verification_failure' => $this->jwsVerificationFailures,
            'built_success' => $this->jwsBuiltSuccesses,
            'built_failure' => $this->jwsBuiltFailures,
        ];
    }
}

<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class NestedTokenBuilderFactory
{
    public function __construct(
        private readonly JWEBuilderFactory $jweBuilderFactory,
        private readonly JWESerializerManagerFactory $jweSerializerManagerFactory,
        private readonly JWSBuilderFactory $jwsBuilderFactory,
        private readonly JWSSerializerManagerFactory $jwsSerializerManagerFactory,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
    }

    public function create(
        array $jwe_serializers,
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithms,
        null|array $compressionMethods,
        array $jws_serializers,
        array $signatureAlgorithms
    ): NestedTokenBuilder {
        if ($contentEncryptionAlgorithms !== null) {
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithms);
        }
        $jweBuilder = $this->jweBuilderFactory->create($encryptionAlgorithms, null, $compressionMethods);
        $jweSerializerManager = $this->jweSerializerManagerFactory->create($jwe_serializers);
        $jwsBuilder = $this->jwsBuilderFactory->create($signatureAlgorithms);
        $jwsSerializerManager = $this->jwsSerializerManagerFactory->create($jws_serializers);

        return new NestedTokenBuilder(
            $jweBuilder,
            $jweSerializerManager,
            $jwsBuilder,
            $jwsSerializerManager,
            $this->eventDispatcher
        );
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\NestedToken;

use Jose\Component\Encryption\JWEBuilderFactory;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;

class NestedTokenBuilderFactory
{
    public function __construct(
        private readonly JWEBuilderFactory $jweBuilderFactory,
        private readonly JWESerializerManagerFactory $jweSerializerManagerFactory,
        private readonly JWSBuilderFactory $jwsBuilderFactory,
        private readonly JWSSerializerManagerFactory $jwsSerializerManagerFactory
    ) {
    }

    /**
     * This method creates a Nested Token Builder with the given encryption/signature algorithms, serializers and
     * compression methods.
     *
     * @param array<string> $jwe_serializers
     * @param array<string> $encryptionAlgorithms
     * @param null|array<string> $contentEncryptionAlgorithms
     * @param null|array<string> $compressionMethods
     * @param array<string> $jws_serializers
     * @param array<string> $signatureAlgorithms
     */
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

        return new NestedTokenBuilder($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager);
    }
}

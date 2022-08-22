<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Serializer;

use function in_array;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use LogicException;
use function mb_strtolower;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;

final class JWSSerializer implements DenormalizerInterface
{
    private readonly JWSSerializerManager $serializerManager;

    public function __construct(
        JWSSerializerManagerFactory $serializerManagerFactory,
        ?JWSSerializerManager $serializerManager = null
    ) {
        if ($serializerManager === null) {
            $serializerManager = $serializerManagerFactory->create($serializerManagerFactory->names());
        }
        $this->serializerManager = $serializerManager;
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        return $type === JWS::class
            && class_exists(JWSSerializerManager::class)
            && $this->formatSupported($format);
    }

    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): JWS
    {
        if ($data instanceof JWS === false) {
            throw new LogicException('Expected data to be a JWS.');
        }

        return $data;
    }

    /**
     * Check if format is supported.
     */
    private function formatSupported(?string $format): bool
    {
        return $format !== null
            && in_array(mb_strtolower($format), $this->serializerManager->list(), true);
    }
}

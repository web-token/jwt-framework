<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Serializer;

use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use LogicException;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use function in_array;
use function mb_strtolower;

final class JWESerializer implements DenormalizerInterface
{
    private readonly JWESerializerManager $serializerManager;

    public function __construct(
        JWESerializerManagerFactory $serializerManagerFactory,
        ?JWESerializerManager $serializerManager = null
    ) {
        if ($serializerManager === null) {
            $serializerManager = $serializerManagerFactory->create($serializerManagerFactory->names());
        }
        $this->serializerManager = $serializerManager;
    }

    public function getSupportedTypes(?string $format): array
    {
        return [
            JWE::class => class_exists(JWESerializerManager::class) && $this->formatSupported($format),
        ];
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = []
    ): bool {
        return $type === JWE::class
            && class_exists(JWESerializerManager::class)
            && $this->formatSupported($format);
    }

    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): JWE
    {
        if ($data instanceof JWE === false) {
            throw new LogicException('Expected data to be a JWE.');
        }

        return $data;
    }

    /**
     * Check if format is supported.
     */
    private function formatSupported(?string $format): bool
    {
        return $format !== null
            && in_array(mb_strtolower($format), $this->serializerManager->names(), true);
    }
}

<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Normalizer;

use ArrayObject;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

final class JWENormalizer implements NormalizerInterface, DenormalizerInterface
{
    /**
     * {@inheritDoc}
     */
    public function supportsNormalization(mixed $data, string $format = null): bool
    {
        return $data instanceof JWE && $this->componentInstalled();
    }

    /**
     * {@inheritDoc}
     */
    public function supportsDenormalization(mixed $data, string $type, string $format = null): bool
    {
        return $type === JWE::class && $this->componentInstalled();
    }

    /**
     * {@inheritDoc}
     */
    public function normalize(
        mixed $object,
        string $format = null,
        array $context = []
    ): array|string|int|float|bool|ArrayObject|null {
        return $object;
    }

    /**
     * @param mixed  $data   Data to restore
     * @param string $type   The expected class to instantiate
     * @param string $format Format the given data was extracted from
     *
     * @return array|object
     */
    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): mixed
    {
        return $data;
    }

    /**
     * Check if encryption component is installed.
     */
    private function componentInstalled(): bool
    {
        return class_exists(JWESerializerManager::class);
    }
}

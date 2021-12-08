<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Normalizer;

use ArrayObject;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

final class JWSNormalizer implements NormalizerInterface, DenormalizerInterface
{
    public function supportsNormalization(mixed $data, string $format = null): bool
    {
        return $data instanceof JWS && $this->componentInstalled();
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null): bool
    {
        return $type === JWS::class && $this->componentInstalled();
    }

    public function normalize(
        mixed $object,
        string $format = null,
        array $context = []
    ): array|string|int|float|bool|ArrayObject|null {
        return $object;
    }

    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): mixed
    {
        return $data;
    }

    /**
     * Check if encryption component is installed.
     */
    private function componentInstalled(): bool
    {
        return class_exists(JWSSerializerManager::class);
    }
}

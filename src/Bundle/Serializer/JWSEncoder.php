<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Serializer;

use Exception;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use LogicException;
use Symfony\Component\Serializer\Encoder\DecoderInterface;
use Symfony\Component\Serializer\Encoder\EncoderInterface;
use Symfony\Component\Serializer\Encoder\NormalizationAwareInterface;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
use function in_array;
use function is_int;
use function mb_strtolower;

final class JWSEncoder implements EncoderInterface, DecoderInterface, NormalizationAwareInterface
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

    public function supportsEncoding(string $format, array $context = []): bool
    {
        return class_exists(JWSSerializerManager::class) && $this->formatSupported($format);
    }

    public function supportsDecoding(string $format, array $context = []): bool
    {
        return class_exists(JWSSerializerManager::class) && $this->formatSupported($format);
    }

    public function encode($data, $format, array $context = []): string
    {
        if ($data instanceof JWS === false) {
            throw new LogicException('Expected data to be a JWS.');
        }

        try {
            return $this->serializerManager->serialize(
                mb_strtolower($format),
                $data,
                $this->getSignatureIndex($context)
            );
        } catch (Exception $ex) {
            throw new NotEncodableValueException(sprintf('Cannot encode JWS to %s format.', $format), 0, $ex);
        }
    }

    public function decode($data, $format, array $context = []): JWS
    {
        try {
            return $this->serializerManager->unserialize($data);
        } catch (Exception $ex) {
            throw new NotEncodableValueException(sprintf('Cannot decode JWS from %s format.', $format), 0, $ex);
        }
    }

    /**
     * Get JWS signature index from context.
     */
    private function getSignatureIndex(array $context): int
    {
        if (isset($context['signature_index']) && is_int($context['signature_index'])) {
            return $context['signature_index'];
        }

        return 0;
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

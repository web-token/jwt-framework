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
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;

use function mb_strtolower;

final class JWSSerializer implements DenormalizerInterface, EncoderInterface, DecoderInterface,
                                     NormalizationAwareInterface
{
    private JWSSerializerManager $serializerManager;

    public function __construct(
        JWSSerializerManagerFactory $serializerManagerFactory,
        ?JWSSerializerManager $serializerManager = null
    ) {
        if ($serializerManager === null) {
            $serializerManager = $serializerManagerFactory->create($serializerManagerFactory->names());
        }
        $this->serializerManager = $serializerManager;
    }

    public function supportsDecoding(string $format): bool
    {
        return $this->formatSupported($format);
    }

    public function supportsEncoding(string $format): bool
    {
        return $this->supportsEncoding($format);
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null): bool
    {
        return $type === JWS::class
            && $this->componentInstalled()
            && $this->formatSupported($format);
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

    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): JWS
    {
        if ($data instanceof JWS === false) {
            throw new LogicException('Expected data to be a JWS.');
        }

        return $data;
    }

    /**
     * Get JWS signature index from context.
     */
    private function getSignatureIndex(array $context): int
    {
        $signatureIndex = 0;
        if (isset($context['signature_index']) && is_int($context['signature_index'])) {
            $signatureIndex = $context['signature_index'];
        }

        return $signatureIndex;
    }

    /**
     * Check if encryption component is installed.
     */
    private function componentInstalled(): bool
    {
        return class_exists(JWESerializerManager::class);
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

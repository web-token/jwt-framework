<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Serializer;

use Exception;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use LogicException;
use Symfony\Component\Serializer\Encoder\DecoderInterface;
use Symfony\Component\Serializer\Encoder\EncoderInterface;
use Symfony\Component\Serializer\Encoder\NormalizationAwareInterface;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Throwable;
use UnexpectedValueException;

use function mb_strtolower;

final class JWESerializer implements DenormalizerInterface, EncoderInterface, DecoderInterface,
                                     NormalizationAwareInterface
{
    private JWESerializerManager $serializerManager;

    public function __construct(
        JWESerializerManagerFactory $serializerManagerFactory,
        ?JWESerializerManager $serializerManager = null
    ) {
        if ($serializerManager === null) {
            $serializerManager = $serializerManagerFactory->create($serializerManagerFactory->names());
        }
        $this->serializerManager = $serializerManager;
    }

    public function supportsEncoding(string $format): bool
    {
        return $this->formatSupported($format);
    }

    public function supportsDecoding(string $format): bool
    {
        return $this->supportsEncoding($format);
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null): bool
    {
        return $type === JWE::class
            && $this->componentInstalled()
            && $this->formatSupported($format);
    }

    public function encode(mixed $data, string $format, array $context = []): string
    {
        if ($data instanceof JWE === false) {
            throw new LogicException('Expected data to be a JWE.');
        }

        try {
            return $this->serializerManager->serialize(
                mb_strtolower($format),
                $data,
                $this->getRecipientIndex($context)
            );
        } catch (Throwable $ex) {
            $message = sprintf('Cannot encode JWE to %s format.', $format);

            if (class_exists('Symfony\Component\Serializer\Exception\NotEncodableValueException')) {
                throw new NotEncodableValueException($message, 0, $ex);
            }

            throw new UnexpectedValueException($message, 0, $ex);
        }
    }

    public function decode(string $data, string $format, array $context = []): JWE
    {
        try {
            return $this->serializerManager->unserialize($data);
        } catch (Exception $ex) {
            $message = sprintf('Cannot decode JWE from %s format.', $format);

            if (class_exists('Symfony\Component\Serializer\Exception\NotEncodableValueException')) {
                throw new NotEncodableValueException($message, 0, $ex);
            }

            throw new UnexpectedValueException($message, 0, $ex);
        }
    }

    public function denormalize(mixed $data, string $type, string $format = null, array $context = []): JWE
    {
        if ($data instanceof JWE === false) {
            throw new LogicException('Expected data to be a JWE.');
        }

        return $data;
    }

    /**
     * Get JWE recipient index from context.
     */
    private function getRecipientIndex(array $context): int
    {
        $recipientIndex = 0;
        if (isset($context['recipient_index']) && is_int($context['recipient_index'])) {
            $recipientIndex = $context['recipient_index'];
        }

        return $recipientIndex;
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
            && in_array(mb_strtolower($format), $this->serializerManager->names(), true);
    }
}

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

namespace Jose\Bundle\JoseFramework\Serializer;

use Exception;
use function in_array;
use function is_int;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Component\Serializer\Encoder\DecoderInterface;
use Symfony\Component\Serializer\Encoder\EncoderInterface;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
use Symfony\Component\Serializer\Exception\UnexpectedValueException;
use Throwable;

final class JWEEncoder implements EncoderInterface, DecoderInterface
{
    /**
     * @var JWESerializerManager
     */
    private $serializerManager;

    public function __construct(
        JWESerializerManagerFactory $serializerManagerFactory,
        ?JWESerializerManager $serializerManager = null
    ) {
        if (null === $serializerManager) {
            $serializerManager = $serializerManagerFactory->create($serializerManagerFactory->names());
        }
        $this->serializerManager = $serializerManager;
    }

    public function supportsEncoding($format): bool
    {
        return in_array(mb_strtolower($format), $this->serializerManager->names(), true);
    }

    public function supportsDecoding($format): bool
    {
        return $this->supportsEncoding($format);
    }

    /**
     * @param mixed $data
     * @param mixed $format
     *
     * @throws NotEncodableValueException if the data cannot be encoded
     * @throws UnexpectedValueException   if the data cannot be encoded
     */
    public function encode($data, $format, array $context = []): string
    {
        try {
            return $this->serializerManager->serialize(mb_strtolower($format), $data, $this->getRecipientIndex($context));
        } catch (Throwable $ex) {
            $message = sprintf('Cannot encode JWE to %s format.', $format);

            if (class_exists('Symfony\Component\Serializer\Exception\NotEncodableValueException')) {
                throw new NotEncodableValueException($message, 0, $ex);
            }

            throw new UnexpectedValueException($message, 0, $ex);
        }
    }

    /**
     * @param mixed $data
     * @param mixed $format
     *
     * @throws NotEncodableValueException if the data cannot be decoded
     * @throws UnexpectedValueException   if the data cannot be decoded
     */
    public function decode($data, $format, array $context = []): JWE
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
}

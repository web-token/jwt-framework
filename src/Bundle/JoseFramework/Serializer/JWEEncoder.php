<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Serializer;

use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Component\Serializer\Encoder\DecoderInterface;
use Symfony\Component\Serializer\Encoder\EncoderInterface;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
use Symfony\Component\Serializer\Exception\UnexpectedValueException;

class JWEEncoder implements EncoderInterface, DecoderInterface
{
    /**
     * @var JWESerializerManager
     */
    protected $serializerManager;

    public function __construct(
        JWESerializerManagerFactory $serializerManagerFactory,
        ?JWESerializerManager $serializerManager = null
    ) {
        if (null === $serializerManager) {
            $serializerManager = $serializerManagerFactory->create($serializerManagerFactory->names());
        }

        $this->serializerManager = $serializerManager;
    }

    public function supportsEncoding($format)
    {
        return \in_array(mb_strtolower($format), $this->serializerManager->list(), true);
    }

    public function supportsDecoding($format)
    {
        return $this->supportsEncoding($format);
    }

    public function encode($data, $format, array $context = [])
    {
        try {
            return $this->serializerManager->serialize(mb_strtolower($format), $data, $this->getRecipientIndex($context));
        } catch (\Exception $ex) {
            $message = sprintf('Cannot encode JWE to %s format.', $format);

            if (\class_exists('Symfony\Component\Serializer\Exception\NotEncodableValueException')) {
                throw new NotEncodableValueException($message, 0, $ex);
            }

            throw new UnexpectedValueException($message, 0, $ex);
        }
    }

    public function decode($data, $format, array $context = [])
    {
        try {
            return $this->serializerManager->unserialize($data);
        } catch (\Exception $ex) {
            $message = sprintf('Cannot decode JWE from %s format.', $format);

            if (\class_exists('Symfony\Component\Serializer\Exception\NotEncodableValueException')) {
                throw new NotEncodableValueException($message, 0, $ex);
            }

            throw new UnexpectedValueException($message, 0, $ex);
        }
    }

    /**
     * Get JWE recipient index from context.
     */
    protected function getRecipientIndex(array $context): int
    {
        $recipientIndex = 0;

        if (isset($context['recipient_index']) && \is_int($context['recipient_index'])) {
            $recipientIndex = $context['recipient_index'];
        }

        return $recipientIndex;
    }
}

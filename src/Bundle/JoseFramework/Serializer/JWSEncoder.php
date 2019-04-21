<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Serializer;

use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Component\Serializer\Encoder\DecoderInterface;
use Symfony\Component\Serializer\Encoder\EncoderInterface;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
use Symfony\Component\Serializer\Exception\UnexpectedValueException;

final class JWSEncoder implements EncoderInterface, DecoderInterface
{
    /**
     * @var JWSSerializerManager
     */
    private $serializerManager;

    public function __construct(
        JWSSerializerManagerFactory $serializerManagerFactory,
        ?JWSSerializerManager $serializerManager = null
    ) {
        if (null === $serializerManager) {
            $serializerManager = $serializerManagerFactory->create($serializerManagerFactory->names());
        }
        $this->serializerManager = $serializerManager;
    }

    public function supportsEncoding($format): bool
    {
        return \in_array(mb_strtolower($format), $this->serializerManager->list(), true);
    }

    public function supportsDecoding($format): bool
    {
        return $this->supportsEncoding($format);
    }

    public function encode($data, $format, array $context = []): string
    {
        try {
            return $this->serializerManager->serialize(mb_strtolower($format), $data, $this->getSignatureIndex($context));
        } catch (\Exception $ex) {
            $message = sprintf('Cannot encode JWS to %s format.', $format);
            if (class_exists('Symfony\Component\Serializer\Exception\NotEncodableValueException')) {
                throw new NotEncodableValueException($message, 0, $ex);
            }

            throw new UnexpectedValueException($message, 0, $ex);
        }
    }

    public function decode($data, $format, array $context = []): JWS
    {
        try {
            return $this->serializerManager->unserialize($data);
        } catch (\Exception $ex) {
            $message = sprintf('Cannot decode JWS from %s format.', $format);
            if (class_exists('Symfony\Component\Serializer\Exception\NotEncodableValueException')) {
                throw new NotEncodableValueException($message, 0, $ex);
            }

            throw new UnexpectedValueException($message, 0, $ex);
        }
    }

    /**
     * Get JWS signature index from context.
     */
    private function getSignatureIndex(array $context): int
    {
        $signatureIndex = 0;
        if (isset($context['signature_index']) && \is_int($context['signature_index'])) {
            $signatureIndex = $context['signature_index'];
        }

        return $signatureIndex;
    }
}

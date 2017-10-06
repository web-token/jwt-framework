<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Serializer;

use Base64Url\Base64Url;
use Jose\Component\Core\Converter\JsonConverterInterface;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Recipient;

/**
 * Class CompactSerializer.
 */
final class CompactSerializer implements JWESerializerInterface
{
    public const NAME = 'jwe_compact';

    /**
     * @var JsonConverterInterface
     */
    private $jsonConverter;

    /**
     * JSONFlattenedSerializer constructor.
     *
     * @param JsonConverterInterface $jsonConverter
     */
    public function __construct(JsonConverterInterface $jsonConverter)
    {
        $this->jsonConverter = $jsonConverter;
    }

    /**
     * {@inheritdoc}
     */
    public function displayName(): string
    {
        return 'JWE Compact';
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function serialize(JWE $jwe, ?int $recipientIndex = null): string
    {
        if (null === $recipientIndex) {
            $recipientIndex = 0;
        }
        $recipient = $jwe->getRecipient($recipientIndex);

        $this->checkHasNoAAD($jwe);
        $this->checkHasSharedProtectedHeaders($jwe);
        $this->checkRecipientHasNoHeaders($jwe, $recipientIndex);

        return sprintf(
            '%s.%s.%s.%s.%s',
            $jwe->getEncodedSharedProtectedHeaders(),
            Base64Url::encode(null === $recipient->getEncryptedKey() ? '' : $recipient->getEncryptedKey()),
            Base64Url::encode(null === $jwe->getIV() ? '' : $jwe->getIV()),
            Base64Url::encode($jwe->getCiphertext()),
            Base64Url::encode(null === $jwe->getTag() ? '' : $jwe->getTag())
        );
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize(string $input): JWE
    {
        $parts = explode('.', $input);
        if (5 !== count($parts)) {
            throw new \InvalidArgumentException('Unsupported input');
        }

        try {
            $encodedSharedProtectedHeader = $parts[0];
            $sharedProtectedHeader = $this->jsonConverter->decode(Base64Url::decode($encodedSharedProtectedHeader));
            $encryptedKey = empty($parts[1]) ? null : Base64Url::decode($parts[1]);
            $iv = Base64Url::decode($parts[2]);
            $ciphertext = Base64Url::decode($parts[3]);
            $tag = Base64Url::decode($parts[4]);

            return JWE::create(
                $ciphertext,
                $iv,
                $tag,
                null,
                [],
                $sharedProtectedHeader,
                $encodedSharedProtectedHeader,
                [Recipient::create([], $encryptedKey)]);
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('Unsupported input');
        } catch (\Error $e) {
            throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param JWE $jwe
     */
    private function checkHasNoAAD(JWE $jwe)
    {
        if (!empty($jwe->getAAD())) {
            throw new \LogicException('This JWE has AAD and cannot be converted into Compact JSON.');
        }
    }

    /**
     * @param JWE $jwe
     * @param int $id
     */
    private function checkRecipientHasNoHeaders(JWE $jwe, int $id)
    {
        if (!empty($jwe->getSharedHeaders()) || !empty($jwe->getRecipient($id)->getHeaders())) {
            throw new \LogicException('This JWE has shared headers or recipient headers and cannot be converted into Compact JSON.');
        }
    }

    /**
     * @param JWE $jwe
     */
    private function checkHasSharedProtectedHeaders(JWE $jwe)
    {
        if (empty($jwe->getSharedProtectedHeaders())) {
            throw new \LogicException('This JWE does not have shared protected headers and cannot be converted into Compact JSON.');
        }
    }
}

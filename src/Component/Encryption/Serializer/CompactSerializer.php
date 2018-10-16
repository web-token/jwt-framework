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

namespace Jose\Component\Encryption\Serializer;

use Base64Url\Base64Url;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Recipient;

final class CompactSerializer implements JWESerializer
{
    public const NAME = 'jwe_compact';

    /**
     * @var JsonConverter
     */
    private $jsonConverter;

    /**
     * JSONFlattenedSerializer constructor.
     */
    public function __construct(JsonConverter $jsonConverter)
    {
        $this->jsonConverter = $jsonConverter;
    }

    public function displayName(): string
    {
        return 'JWE Compact';
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function serialize(JWE $jwe, ?int $recipientIndex = null): string
    {
        if (null === $recipientIndex) {
            $recipientIndex = 0;
        }
        $recipient = $jwe->getRecipient($recipientIndex);

        $this->checkHasNoAAD($jwe);
        $this->checkHasSharedProtectedHeader($jwe);
        $this->checkRecipientHasNoHeader($jwe, $recipientIndex);

        return \sprintf(
            '%s.%s.%s.%s.%s',
            $jwe->getEncodedSharedProtectedHeader(),
            Base64Url::encode(null === $recipient->getEncryptedKey() ? '' : $recipient->getEncryptedKey()),
            Base64Url::encode(null === $jwe->getIV() ? '' : $jwe->getIV()),
            Base64Url::encode($jwe->getCiphertext()),
            Base64Url::encode(null === $jwe->getTag() ? '' : $jwe->getTag())
        );
    }

    public function unserialize(string $input): JWE
    {
        $parts = \explode('.', $input);
        if (5 !== \count($parts)) {
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
        } catch (\Error | \Exception $e) {
            throw new \InvalidArgumentException('Unsupported input');
        }
    }

    private function checkHasNoAAD(JWE $jwe)
    {
        if (!empty($jwe->getAAD())) {
            throw new \LogicException('This JWE has AAD and cannot be converted into Compact JSON.');
        }
    }

    private function checkRecipientHasNoHeader(JWE $jwe, int $id)
    {
        if (!empty($jwe->getSharedHeader()) || !empty($jwe->getRecipient($id)->getHeader())) {
            throw new \LogicException('This JWE has shared header parameters or recipient header parameters and cannot be converted into Compact JSON.');
        }
    }

    private function checkHasSharedProtectedHeader(JWE $jwe)
    {
        if (empty($jwe->getSharedProtectedHeader())) {
            throw new \LogicException('This JWE does not have shared protected header parameters and cannot be converted into Compact JSON.');
        }
    }
}

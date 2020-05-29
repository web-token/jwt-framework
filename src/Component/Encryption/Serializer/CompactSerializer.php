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

namespace Jose\Component\Encryption\Serializer;

use Base64Url\Base64Url;
use function count;
use InvalidArgumentException;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Recipient;
use LogicException;
use Throwable;

final class CompactSerializer implements JWESerializer
{
    public const NAME = 'jwe_compact';

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

        return sprintf(
            '%s.%s.%s.%s.%s',
            $jwe->getEncodedSharedProtectedHeader(),
            Base64Url::encode(null === $recipient->getEncryptedKey() ? '' : $recipient->getEncryptedKey()),
            Base64Url::encode(null === $jwe->getIV() ? '' : $jwe->getIV()),
            Base64Url::encode($jwe->getCiphertext()),
            Base64Url::encode(null === $jwe->getTag() ? '' : $jwe->getTag())
        );
    }

    /**
     * @throws InvalidArgumentException if the input is not supported
     */
    public function unserialize(string $input): JWE
    {
        $parts = explode('.', $input);
        if (5 !== count($parts)) {
            throw new InvalidArgumentException('Unsupported input');
        }

        try {
            $encodedSharedProtectedHeader = $parts[0];
            $sharedProtectedHeader = JsonConverter::decode(Base64Url::decode($encodedSharedProtectedHeader));
            $encryptedKey = '' === $parts[1] ? null : Base64Url::decode($parts[1]);
            $iv = Base64Url::decode($parts[2]);
            $ciphertext = Base64Url::decode($parts[3]);
            $tag = Base64Url::decode($parts[4]);

            return new JWE(
                $ciphertext,
                $iv,
                $tag,
                null,
                [],
                $sharedProtectedHeader,
                $encodedSharedProtectedHeader,
                [new Recipient([], $encryptedKey)]
            );
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unsupported input', $throwable->getCode(), $throwable);
        }
    }

    /**
     * @throws LogicException if the AAD is invalid
     */
    private function checkHasNoAAD(JWE $jwe): void
    {
        if (null !== $jwe->getAAD()) {
            throw new LogicException('This JWE has AAD and cannot be converted into Compact JSON.');
        }
    }

    /**
     * @throws LogicException if the JWE has a shared header or recipient header (invalid for compact JSON)
     */
    private function checkRecipientHasNoHeader(JWE $jwe, int $id): void
    {
        if (0 !== count($jwe->getSharedHeader()) || 0 !== count($jwe->getRecipient($id)->getHeader())) {
            throw new LogicException('This JWE has shared header parameters or recipient header parameters and cannot be converted into Compact JSON.');
        }
    }

    /**
     * @throws LogicException if the JWE has no shared protected header (invalid for compact JSON)
     */
    private function checkHasSharedProtectedHeader(JWE $jwe): void
    {
        if (0 === count($jwe->getSharedProtectedHeader())) {
            throw new LogicException('This JWE does not have shared protected header parameters and cannot be converted into Compact JSON.');
        }
    }
}

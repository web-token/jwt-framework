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

use function array_key_exists;
use Base64Url\Base64Url;
use function count;
use InvalidArgumentException;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Recipient;
use LogicException;

final class JSONGeneralSerializer implements JWESerializer
{
    public const NAME = 'jwe_json_general';

    public function displayName(): string
    {
        return 'JWE JSON General';
    }

    public function name(): string
    {
        return self::NAME;
    }

    /**
     * @throws LogicException if there is no recipient
     */
    public function serialize(JWE $jwe, ?int $recipientIndex = null): string
    {
        if (0 === $jwe->countRecipients()) {
            throw new LogicException('No recipient.');
        }

        $data = [
            'ciphertext' => Base64Url::encode($jwe->getCiphertext()),
            'iv' => Base64Url::encode($jwe->getIV()),
            'tag' => Base64Url::encode($jwe->getTag()),
        ];
        if (null !== $jwe->getAAD()) {
            $data['aad'] = Base64Url::encode($jwe->getAAD());
        }
        if (0 !== count($jwe->getSharedProtectedHeader())) {
            $data['protected'] = $jwe->getEncodedSharedProtectedHeader();
        }
        if (0 !== count($jwe->getSharedHeader())) {
            $data['unprotected'] = $jwe->getSharedHeader();
        }
        $data['recipients'] = [];
        foreach ($jwe->getRecipients() as $recipient) {
            $temp = [];
            if (0 !== count($recipient->getHeader())) {
                $temp['header'] = $recipient->getHeader();
            }
            if (null !== $recipient->getEncryptedKey()) {
                $temp['encrypted_key'] = Base64Url::encode($recipient->getEncryptedKey());
            }
            $data['recipients'][] = $temp;
        }

        return JsonConverter::encode($data);
    }

    public function unserialize(string $input): JWE
    {
        $data = JsonConverter::decode($input);
        $this->checkData($data);

        $ciphertext = Base64Url::decode($data['ciphertext']);
        $iv = Base64Url::decode($data['iv']);
        $tag = Base64Url::decode($data['tag']);
        $aad = array_key_exists('aad', $data) ? Base64Url::decode($data['aad']) : null;
        [$encodedSharedProtectedHeader, $sharedProtectedHeader, $sharedHeader] = $this->processHeaders($data);
        $recipients = [];
        foreach ($data['recipients'] as $recipient) {
            [$encryptedKey, $header] = $this->processRecipient($recipient);
            $recipients[] = new Recipient($header, $encryptedKey);
        }

        return new JWE(
            $ciphertext,
            $iv,
            $tag,
            $aad,
            $sharedHeader,
            $sharedProtectedHeader,
            $encodedSharedProtectedHeader,
            $recipients
        );
    }

    /**
     * @throws InvalidArgumentException if the input is not supported
     */
    private function checkData(?array $data): void
    {
        if (null === $data || !isset($data['ciphertext']) || !isset($data['recipients'])) {
            throw new InvalidArgumentException('Unsupported input.');
        }
    }

    private function processRecipient(array $recipient): array
    {
        $encryptedKey = array_key_exists('encrypted_key', $recipient) ? Base64Url::decode($recipient['encrypted_key']) : null;
        $header = array_key_exists('header', $recipient) ? $recipient['header'] : [];

        return [$encryptedKey, $header];
    }

    private function processHeaders(array $data): array
    {
        $encodedSharedProtectedHeader = array_key_exists('protected', $data) ? $data['protected'] : null;
        $sharedProtectedHeader = $encodedSharedProtectedHeader ? JsonConverter::decode(Base64Url::decode($encodedSharedProtectedHeader)) : [];
        $sharedHeader = array_key_exists('unprotected', $data) ? $data['unprotected'] : [];

        return [$encodedSharedProtectedHeader, $sharedProtectedHeader, $sharedHeader];
    }
}

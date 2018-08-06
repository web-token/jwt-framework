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

final class JSONFlattenedSerializer implements JWESerializer
{
    public const NAME = 'jwe_json_flattened';

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
        return 'JWE JSON Flattened';
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
        $data = [
            'ciphertext' => Base64Url::encode($jwe->getCiphertext()),
            'iv' => Base64Url::encode($jwe->getIV()),
            'tag' => Base64Url::encode($jwe->getTag()),
        ];
        if (null !== $jwe->getAAD()) {
            $data['aad'] = Base64Url::encode($jwe->getAAD());
        }
        if (!empty($jwe->getSharedProtectedHeader())) {
            $data['protected'] = $jwe->getEncodedSharedProtectedHeader();
        }
        if (!empty($jwe->getSharedHeader())) {
            $data['unprotected'] = $jwe->getSharedHeader();
        }
        if (!empty($recipient->getHeader())) {
            $data['header'] = $recipient->getHeader();
        }
        if (null !== $recipient->getEncryptedKey()) {
            $data['encrypted_key'] = Base64Url::encode($recipient->getEncryptedKey());
        }

        return $this->jsonConverter->encode($data);
    }

    public function unserialize(string $input): JWE
    {
        $data = $this->jsonConverter->decode($input);
        $this->checkData($data);

        $ciphertext = Base64Url::decode($data['ciphertext']);
        $iv = Base64Url::decode($data['iv']);
        $tag = Base64Url::decode($data['tag']);
        $aad = \array_key_exists('aad', $data) ? Base64Url::decode($data['aad']) : null;
        list($encodedSharedProtectedHeader, $sharedProtectedHeader, $sharedHeader) = $this->processHeaders($data);
        $encryptedKey = \array_key_exists('encrypted_key', $data) ? Base64Url::decode($data['encrypted_key']) : null;
        $header = \array_key_exists('header', $data) ? $data['header'] : [];

        return JWE::create(
            $ciphertext,
            $iv,
            $tag,
            $aad,
            $sharedHeader,
            $sharedProtectedHeader,
            $encodedSharedProtectedHeader,
            [Recipient::create($header, $encryptedKey)]);
    }

    private function checkData($data)
    {
        if (!\is_array($data) || !\array_key_exists('ciphertext', $data) || \array_key_exists('recipients', $data)) {
            throw new \InvalidArgumentException('Unsupported input.');
        }
    }

    private function processHeaders(array $data): array
    {
        $encodedSharedProtectedHeader = \array_key_exists('protected', $data) ? $data['protected'] : null;
        $sharedProtectedHeader = $encodedSharedProtectedHeader ? $this->jsonConverter->decode(Base64Url::decode($encodedSharedProtectedHeader)) : [];
        $sharedHeader = \array_key_exists('unprotected', $data) ? $data['unprotected'] : [];

        return [$encodedSharedProtectedHeader, $sharedProtectedHeader, $sharedHeader];
    }
}

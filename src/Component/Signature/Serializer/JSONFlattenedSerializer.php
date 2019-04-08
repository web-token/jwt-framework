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

namespace Jose\Component\Signature\Serializer;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWS;

final class JSONFlattenedSerializer extends Serializer
{
    public const NAME = 'jws_json_flattened';

    public function displayName(): string
    {
        return 'JWS JSON Flattened';
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function serialize(JWS $jws, ?int $signatureIndex = null): string
    {
        if (null === $signatureIndex) {
            $signatureIndex = 0;
        }
        $signature = $jws->getSignature($signatureIndex);

        $data = [];
        $values = [
            'payload' => $jws->getEncodedPayload(),
            'protected' => $signature->getEncodedProtectedHeader(),
            'header' => $signature->getHeader(),
        ];
        $encodedPayload = $jws->getEncodedPayload();
        if (null !== $encodedPayload && '' !== $encodedPayload) {
            $data['payload'] = $encodedPayload;
        }
        $encodedProtectedHeader = $signature->getEncodedProtectedHeader();
        if (null !== $encodedProtectedHeader && '' !== $encodedProtectedHeader) {
            $data['protected'] = $encodedProtectedHeader;
        }
        $header = $signature->getHeader();
        if (0 !== \count($header)) {
            $data['header'] = $header;
        }
        $data['signature'] = Base64Url::encode($signature->getSignature());

        return JsonConverter::encode($data);
    }

    public function unserialize(string $input): JWS
    {
        $data = JsonConverter::decode($input);
        Assertion::isArray($data, 'Unsupported input.');
        Assertion::keyExists($data, 'signature', 'Unsupported input.');
        $signature = Base64Url::decode($data['signature']);

        if (\array_key_exists('protected', $data)) {
            $encodedProtectedHeader = $data['protected'];
            $protectedHeader = JsonConverter::decode(Base64Url::decode($data['protected']));
        } else {
            $encodedProtectedHeader = null;
            $protectedHeader = [];
        }
        if (\array_key_exists('header', $data)) {
            Assertion::isArray($data['header'], 'Bad header.');
            $header = $data['header'];
        } else {
            $header = [];
        }

        if (\array_key_exists('payload', $data)) {
            $encodedPayload = $data['payload'];
            $payload = $this->isPayloadEncoded($protectedHeader) ? Base64Url::decode($encodedPayload) : $encodedPayload;
        } else {
            $payload = null;
            $encodedPayload = null;
        }

        $jws = new JWS($payload, $encodedPayload, null === $encodedPayload);
        $jws = $jws->addSignature($signature, $protectedHeader, $encodedProtectedHeader, $header);

        return $jws;
    }
}

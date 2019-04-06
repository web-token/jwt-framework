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

namespace Jose\Component\Signature\Serializer;

use Base64Url\Base64Url;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Signature\JWS;

final class JSONFlattenedSerializer extends Serializer
{
    public const NAME = 'jws_json_flattened';

    /**
     * @var JsonConverter|\Jose\Component\Core\Util\JsonConverter|null
     */
    private $jsonConverter;

    /**
     * JSONFlattenedSerializer constructor.
     */
    public function __construct(?JsonConverter $jsonConverter = null)
    {
        $this->jsonConverter = $jsonConverter ?? new \Jose\Component\Core\Util\JsonConverter();
    }

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

        foreach ($values as $key => $value) {
            if (!empty($value)) {
                $data[$key] = $value;
            }
        }
        $data['signature'] = Base64Url::encode($signature->getSignature());

        return $this->jsonConverter->encode($data);
    }

    public function unserialize(string $input): JWS
    {
        $data = $this->jsonConverter->decode($input);
        if (!\is_array($data) || !\array_key_exists('signature', $data)) {
            throw new \InvalidArgumentException('Unsupported input.');
        }

        $signature = Base64Url::decode($data['signature']);

        if (\array_key_exists('protected', $data)) {
            $encodedProtectedHeader = $data['protected'];
            $protectedHeader = $this->jsonConverter->decode(Base64Url::decode($data['protected']));
        } else {
            $encodedProtectedHeader = null;
            $protectedHeader = [];
        }
        if (\array_key_exists('header', $data)) {
            if (!\is_array($data['header'])) {
                throw new \InvalidArgumentException('Bad header.');
            }
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

        $jws = JWS::create($payload, $encodedPayload, null === $encodedPayload);
        $jws = $jws->addSignature($signature, $protectedHeader, $encodedProtectedHeader, $header);

        return $jws;
    }
}

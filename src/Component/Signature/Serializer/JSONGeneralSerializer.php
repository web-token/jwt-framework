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

final class JSONGeneralSerializer extends Serializer
{
    public const NAME = 'jws_json_general';

    /**
     * @var \Jose\Component\Core\Util\JsonConverter
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
        return 'JWS JSON General';
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function serialize(JWS $jws, ?int $signatureIndex = null): string
    {
        if (0 === $jws->countSignatures()) {
            throw new \LogicException('No signature.');
        }

        $data = [];
        $this->checkPayloadEncoding($jws);

        if (false === $jws->isPayloadDetached()) {
            $data['payload'] = $jws->getEncodedPayload();
        }

        $data['signatures'] = [];
        foreach ($jws->getSignatures() as $signature) {
            $tmp = ['signature' => Base64Url::encode($signature->getSignature())];
            $values = [
                'protected' => $signature->getEncodedProtectedHeader(),
                'header' => $signature->getHeader(),
            ];

            foreach ($values as $key => $value) {
                if (!empty($value)) {
                    $tmp[$key] = $value;
                }
            }
            $data['signatures'][] = $tmp;
        }

        return $this->jsonConverter->encode($data);
    }

    private function checkData($data)
    {
        if (!\is_array($data) || !\array_key_exists('signatures', $data)) {
            throw new \InvalidArgumentException('Unsupported input.');
        }
    }

    private function checkSignature($signature)
    {
        if (!\is_array($signature) || !\array_key_exists('signature', $signature)) {
            throw new \InvalidArgumentException('Unsupported input.');
        }
    }

    public function unserialize(string $input): JWS
    {
        $data = $this->jsonConverter->decode($input);
        $this->checkData($data);

        $isPayloadEncoded = null;
        $rawPayload = \array_key_exists('payload', $data) ? $data['payload'] : null;
        $signatures = [];
        foreach ($data['signatures'] as $signature) {
            $this->checkSignature($signature);
            list($encodedProtectedHeader, $protectedHeader, $header) = $this->processHeaders($signature);
            $signatures[] = [
                'signature' => Base64Url::decode($signature['signature']),
                'protected' => $protectedHeader,
                'encoded_protected' => $encodedProtectedHeader,
                'header' => $header,
            ];
            $isPayloadEncoded = $this->processIsPayloadEncoded($isPayloadEncoded, $protectedHeader);
        }

        $payload = $this->processPayload($rawPayload, $isPayloadEncoded);
        $jws = JWS::create($payload, $rawPayload);
        foreach ($signatures as $signature) {
            $jws = $jws->addSignature(
                $signature['signature'],
                $signature['protected'],
                $signature['encoded_protected'],
                $signature['header']
            );
        }

        return $jws;
    }

    private function processIsPayloadEncoded(?bool $isPayloadEncoded, array $protectedHeader): bool
    {
        if (null === $isPayloadEncoded) {
            return self::isPayloadEncoded($protectedHeader);
        }
        if ($this->isPayloadEncoded($protectedHeader) !== $isPayloadEncoded) {
            throw new \InvalidArgumentException('Foreign payload encoding detected.');
        }

        return $isPayloadEncoded;
    }

    private function processHeaders(array $signature): array
    {
        $encodedProtectedHeader = \array_key_exists('protected', $signature) ? $signature['protected'] : null;
        $protectedHeader = null !== $encodedProtectedHeader ? $this->jsonConverter->decode(Base64Url::decode($encodedProtectedHeader)) : [];
        $header = \array_key_exists('header', $signature) ? $signature['header'] : [];

        return [$encodedProtectedHeader, $protectedHeader, $header];
    }

    private function processPayload(?string $rawPayload, ?bool $isPayloadEncoded): ?string
    {
        if (null === $rawPayload) {
            return null;
        }

        return false === $isPayloadEncoded ? $rawPayload : Base64Url::decode($rawPayload);
    }

    private function checkPayloadEncoding(JWS $jws)
    {
        if ($jws->isPayloadDetached()) {
            return;
        }
        $is_encoded = null;
        foreach ($jws->getSignatures() as $signature) {
            if (null === $is_encoded) {
                $is_encoded = $this->isPayloadEncoded($signature->getProtectedHeader());
            }
            if (false === $jws->isPayloadDetached()) {
                if ($is_encoded !== $this->isPayloadEncoded($signature->getProtectedHeader())) {
                    throw new \LogicException('Foreign payload encoding detected.');
                }
            }
        }
    }
}

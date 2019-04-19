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
use LogicException;

final class JSONGeneralSerializer extends Serializer
{
    public const NAME = 'jws_json_general';

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
            throw new LogicException('No signature.');
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
                if ((\is_string($value) && '' !== $value) || (\is_array($value) && 0 !== \count($value))) {
                    $tmp[$key] = $value;
                }
            }
            $data['signatures'][] = $tmp;
        }

        return JsonConverter::encode($data);
    }

    public function unserialize(string $input): JWS
    {
        $data = JsonConverter::decode($input);
        Assertion::keyExists($data, 'signatures', 'Unsupported input.');

        $isPayloadEncoded = null;
        $rawPayload = \array_key_exists('payload', $data) ? $data['payload'] : null;
        $signatures = [];
        foreach ($data['signatures'] as $signature) {
            Assertion::keyExists($signature, 'signature', 'Unsupported input.');
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
        $jws = new JWS($payload, $rawPayload);
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
            return $this->isPayloadEncoded($protectedHeader);
        }
        Assertion::eq($this->isPayloadEncoded($protectedHeader), $isPayloadEncoded, 'Foreign payload encoding detected.');

        return $isPayloadEncoded;
    }

    private function processHeaders(array $signature): array
    {
        $encodedProtectedHeader = $signature['protected'] ?? null;
        $protectedHeader = null !== $encodedProtectedHeader ? JsonConverter::decode(Base64Url::decode($encodedProtectedHeader)) : [];
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

    private function checkPayloadEncoding(JWS $jws): void
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
                    throw new LogicException('Foreign payload encoding detected.');
                }
            }
        }
    }
}

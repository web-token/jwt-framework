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

namespace Jose\Component\Signature\Serializer;

use Base64Url\Base64Url;
use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Signature\JWS;

/**
 * Class JSONGeneralSerializer.
 */
final class JSONGeneralSerializer extends Serializer
{
    public const NAME = 'jws_json_general';

    /**
     * @var JsonConverter
     */
    private $jsonConverter;

    /**
     * JSONFlattenedSerializer constructor.
     *
     * @param JsonConverter $jsonConverter
     */
    public function __construct(JsonConverter $jsonConverter)
    {
        $this->jsonConverter = $jsonConverter;
    }

    /**
     * {@inheritdoc}
     */
    public function displayName(): string
    {
        return 'JWS JSON General';
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
                'protected' => $signature->getEncodedProtectedHeaders(),
                'header' => $signature->getHeaders(),
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

    /**
     * @param $data
     */
    private function checkData($data)
    {
        if (!is_array($data) || !array_key_exists('signatures', $data)) {
            throw new \InvalidArgumentException('Unsupported input.');
        }
    }

    /**
     * @param $signature
     */
    private function checkSignature($signature)
    {
        if (!is_array($signature) || !array_key_exists('signature', $signature)) {
            throw new \InvalidArgumentException('Unsupported input.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize(string $input): JWS
    {
        $data = $this->jsonConverter->decode($input);
        $this->checkData($data);

        $isPayloadEncoded = null;
        $rawPayload = array_key_exists('payload', $data) ? $data['payload'] : null;
        $signatures = [];
        foreach ($data['signatures'] as $signature) {
            $this->checkSignature($signature);
            list($encodedProtectedHeaders, $protectedHeaders, $headers) = $this->processHeaders($signature);
            $signatures[] = [
                'signature' => Base64Url::decode($signature['signature']),
                'protected' => $protectedHeaders,
                'encoded_protected' => $encodedProtectedHeaders,
                'header' => $headers,
            ];
            $isPayloadEncoded = $this->processIsPayloadEncoded($isPayloadEncoded, $protectedHeaders);
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

    /**
     * @param bool|null $isPayloadEncoded
     * @param array     $protectedHeaders
     *
     * @return bool
     */
    private function processIsPayloadEncoded(?bool $isPayloadEncoded, array $protectedHeaders): bool
    {
        if (null === $isPayloadEncoded) {
            return self::isPayloadEncoded($protectedHeaders);
        }
        if ($this->isPayloadEncoded($protectedHeaders) !== $isPayloadEncoded) {
            throw new \InvalidArgumentException('Foreign payload encoding detected.');
        }

        return $isPayloadEncoded;
    }

    /**
     * @param array $signature
     *
     * @return array
     */
    private function processHeaders(array $signature): array
    {
        $encodedProtectedHeaders = array_key_exists('protected', $signature) ? $signature['protected'] : null;
        $protectedHeaders = null !== $encodedProtectedHeaders ? $this->jsonConverter->decode(Base64Url::decode($encodedProtectedHeaders)) : [];
        $headers = array_key_exists('header', $signature) ? $signature['header'] : [];

        return [$encodedProtectedHeaders, $protectedHeaders, $headers];
    }

    /**
     * @param null|string $rawPayload
     * @param bool|null   $isPayloadEncoded
     *
     * @return null|string
     */
    private function processPayload(?string $rawPayload, ?bool $isPayloadEncoded): ?string
    {
        if (null === $rawPayload) {
            return null;
        }

        return false === $isPayloadEncoded ? $rawPayload : Base64Url::decode($rawPayload);
    }

    /**
     * @param JWS $jws
     */
    private function checkPayloadEncoding(JWS $jws)
    {
        if ($jws->isPayloadDetached()) {
            return;
        }
        $is_encoded = null;
        foreach ($jws->getSignatures() as $signature) {
            if (null === $is_encoded) {
                $is_encoded = $this->isPayloadEncoded($signature->getProtectedHeaders());
            }
            if (false === $jws->isPayloadDetached()) {
                if ($is_encoded !== $this->isPayloadEncoded($signature->getProtectedHeaders())) {
                    throw new \LogicException('Foreign payload encoding detected.');
                }
            }
        }
    }
}

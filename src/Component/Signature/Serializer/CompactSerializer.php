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
 * Class CompactSerializer.
 */
final class CompactSerializer extends AbstractSerializer
{
    public const NAME = 'jws_compact';

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
        return 'JWS Compact';
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
        if (null === $signatureIndex) {
            $signatureIndex = 0;
        }
        $signature = $jws->getSignature($signatureIndex);
        if (!empty($signature->getHeaders())) {
            throw new \LogicException('The signature contains unprotected headers and cannot be converted into compact JSON.');
        }
        if (!$this->isPayloadEncoded($signature->getProtectedHeaders()) && !empty($jws->getEncodedPayload())) {
            if (1 !== preg_match('/^[\x{20}-\x{2d}|\x{2f}-\x{7e}]*$/u', $jws->getPayload())) {
                throw new \LogicException('Unable to convert the JWS with non-encoded payload.');
            }
        }

        return sprintf(
            '%s.%s.%s',
            $signature->getEncodedProtectedHeaders(),
            $jws->getEncodedPayload(),
            Base64Url::encode($signature->getSignature())
        );
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize(string $input): JWS
    {
        $parts = explode('.', $input);
        if (3 !== count($parts)) {
            throw new \InvalidArgumentException('Unsupported input');
        }

        try {
            $encodedProtectedHeaders = $parts[0];
            $protectedHeaders = $this->jsonConverter->decode(Base64Url::decode($parts[0]));
            if (empty($parts[1])) {
                $payload = null;
                $encodedPayload = null;
            } else {
                $encodedPayload = $parts[1];
                $payload = $this->isPayloadEncoded($protectedHeaders) ? Base64Url::decode($encodedPayload) : $encodedPayload;
            }
            $signature = Base64Url::decode($parts[2]);

            $jws = JWS::create($payload, $encodedPayload, empty($parts[1]));
            $jws = $jws->addSignature($signature, $protectedHeaders, $encodedProtectedHeaders);

            return $jws;
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('Unsupported input');
        } catch (\Error $e) {
            throw new \InvalidArgumentException('Unsupported input');
        }
    }
}

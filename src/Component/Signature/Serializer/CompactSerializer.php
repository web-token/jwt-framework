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

final class CompactSerializer extends Serializer
{
    public const NAME = 'jws_compact';

    /**
     * @var JsonConverter
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
        return 'JWS Compact';
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
        if (!empty($signature->getHeader())) {
            throw new \LogicException('The signature contains unprotected header parameters and cannot be converted into compact JSON.');
        }
        if (!$this->isPayloadEncoded($signature->getProtectedHeader()) && !empty($jws->getEncodedPayload())) {
            if (1 !== \preg_match('/^[\x{20}-\x{2d}|\x{2f}-\x{7e}]*$/u', $jws->getPayload())) {
                throw new \LogicException('Unable to convert the JWS with non-encoded payload.');
            }
        }

        return \sprintf(
            '%s.%s.%s',
            $signature->getEncodedProtectedHeader(),
            $jws->getEncodedPayload(),
            Base64Url::encode($signature->getSignature())
        );
    }

    public function unserialize(string $input): JWS
    {
        $parts = \explode('.', $input);
        if (3 !== \count($parts)) {
            throw new \InvalidArgumentException('Unsupported input');
        }

        try {
            $encodedProtectedHeader = $parts[0];
            $protectedHeader = $this->jsonConverter->decode(Base64Url::decode($parts[0]));
            if (empty($parts[1])) {
                $payload = null;
                $encodedPayload = null;
            } else {
                $encodedPayload = $parts[1];
                $payload = $this->isPayloadEncoded($protectedHeader) ? Base64Url::decode($encodedPayload) : $encodedPayload;
            }
            $signature = Base64Url::decode($parts[2]);

            $jws = JWS::create($payload, $encodedPayload, empty($parts[1]));
            $jws = $jws->addSignature($signature, $protectedHeader, $encodedProtectedHeader);

            return $jws;
        } catch (\Error | \Exception $e) {
            throw new \InvalidArgumentException('Unsupported input');
        }
    }
}

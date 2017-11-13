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

namespace Jose\Component\Signature;

use Base64Url\Base64Url;
use Jose\Component\Core\Converter\JsonConverterInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Signature\Algorithm\SignatureAlgorithmInterface;

/**
 * Class JWSBuilder.
 */
final class JWSBuilder
{
    /**
     * @var JsonConverterInterface
     */
    private $jsonConverter;

    /**
     * @var string
     */
    private $payload;

    /**
     * @var bool
     */
    private $isPayloadDetached;

    /**
     * @var array
     */
    private $signatures = [];

    /**
     * @var AlgorithmManager
     */
    private $signatureAlgorithmManager;

    /**
     * @var null|bool
     */
    private $isPayloadEncoded = null;

    /**
     * JWSBuilder constructor.
     *
     * @param JsonConverterInterface $jsonConverter
     * @param AlgorithmManager       $signatureAlgorithmManager
     */
    public function __construct(JsonConverterInterface $jsonConverter, AlgorithmManager $signatureAlgorithmManager)
    {
        $this->jsonConverter = $jsonConverter;
        $this->signatureAlgorithmManager = $signatureAlgorithmManager;
    }

    /**
     * @return AlgorithmManager
     */
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->signatureAlgorithmManager;
    }

    /**
     * Reset the current data.
     *
     * @return JWSBuilder
     */
    public function create(): self
    {
        $this->payload = null;
        $this->isPayloadDetached = null;
        $this->signatures = [];
        $this->isPayloadEncoded = null;

        return $this;
    }

    /**
     * @param string $payload
     * @param bool   $isPayloadDetached
     *
     * @return JWSBuilder
     */
    public function withPayload(string $payload, bool $isPayloadDetached = false): self
    {
        if (false === mb_detect_encoding($payload, 'UTF-8', true)) {
            throw new \InvalidArgumentException('The payload must be encoded in UTF-8');
        }
        $clone = clone $this;
        $clone->payload = $payload;
        $clone->isPayloadDetached = $isPayloadDetached;

        return $clone;
    }

    /**
     * @param JWK   $signatureKey
     * @param array $protectedHeaders
     * @param array $headers
     *
     * @return JWSBuilder
     */
    public function addSignature(JWK $signatureKey, array $protectedHeaders, array $headers = []): self
    {
        $this->checkB64AndCriticalHeader($protectedHeaders);
        $isPayloadEncoded = $this->checkIfPayloadIsEncoded($protectedHeaders);
        if (null === $this->isPayloadEncoded) {
            $this->isPayloadEncoded = $isPayloadEncoded;
        } elseif ($this->isPayloadEncoded !== $isPayloadEncoded) {
            throw new \InvalidArgumentException('Foreign payload encoding detected.');
        }
        $this->checkDuplicatedHeaderParameters($protectedHeaders, $headers);
        KeyChecker::checkKeyUsage($signatureKey, 'signature');
        $signatureAlgorithm = $this->findSignatureAlgorithm($signatureKey, $protectedHeaders, $headers);
        KeyChecker::checkKeyAlgorithm($signatureKey, $signatureAlgorithm->name());
        $clone = clone $this;
        $clone->signatures[] = [
            'signature_algorithm' => $signatureAlgorithm,
            'signature_key' => $signatureKey,
            'protected_headers' => $protectedHeaders,
            'headers' => $headers,
        ];

        return $clone;
    }

    /**
     * @return JWS
     */
    public function build(): JWS
    {
        if (null === $this->payload) {
            throw new \RuntimeException('The payload is not set.');
        }
        if (0 === count($this->signatures)) {
            throw new \RuntimeException('At least one signature must be set.');
        }

        $encodedPayload = false === $this->isPayloadEncoded ? $this->payload : Base64Url::encode($this->payload);
        $jws = JWS::create($this->payload, $encodedPayload, $this->isPayloadDetached);
        foreach ($this->signatures as $signature) {
            /** @var SignatureAlgorithmInterface $signatureAlgorithm */
            $signatureAlgorithm = $signature['signature_algorithm'];
            /** @var JWK $signatureKey */
            $signatureKey = $signature['signature_key'];
            /** @var array $protectedHeaders */
            $protectedHeaders = $signature['protected_headers'];
            /** @var array $headers */
            $headers = $signature['headers'];
            $encodedProtectedHeaders = empty($protectedHeaders) ? null : Base64Url::encode($this->jsonConverter->encode($protectedHeaders));
            $input = sprintf('%s.%s', $encodedProtectedHeaders, $encodedPayload);
            $s = $signatureAlgorithm->sign($signatureKey, $input);
            $jws = $jws->addSignature($s, $protectedHeaders, $encodedProtectedHeaders, $headers);
        }

        return $jws;
    }

    /**
     * @param array $protectedHeaders
     *
     * @return bool
     */
    private function checkIfPayloadIsEncoded(array $protectedHeaders): bool
    {
        return !array_key_exists('b64', $protectedHeaders) || true === $protectedHeaders['b64'];
    }

    /**
     * @param array $protectedHeaders
     */
    private function checkB64AndCriticalHeader(array $protectedHeaders)
    {
        if (!array_key_exists('b64', $protectedHeaders)) {
            return;
        }
        if (!array_key_exists('crit', $protectedHeaders)) {
            throw new \LogicException('The protected header parameter "crit" is mandatory when protected header parameter "b64" is set.');
        }
        if (!is_array($protectedHeaders['crit'])) {
            throw new \LogicException('The protected header parameter "crit" must be an array.');
        }
        if (!in_array('b64', $protectedHeaders['crit'])) {
            throw new \LogicException('The protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set.');
        }
    }

    /**
     * @param array $protectedHeader
     * @param array $headers
     * @param JWK   $key
     *
     * @return SignatureAlgorithmInterface
     */
    private function findSignatureAlgorithm(JWK $key, array $protectedHeader, array $headers): SignatureAlgorithmInterface
    {
        $completeHeader = array_merge($headers, $protectedHeader);
        if (!array_key_exists('alg', $completeHeader)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }
        if ($key->has('alg') && $key->get('alg') !== $completeHeader['alg']) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not allowed with this key.', $completeHeader['alg']));
        }

        $signatureAlgorithm = $this->signatureAlgorithmManager->get($completeHeader['alg']);
        if (!$signatureAlgorithm instanceof SignatureAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $completeHeader['alg']));
        }

        return $signatureAlgorithm;
    }

    /**
     * @param array $header1
     * @param array $header2
     */
    private function checkDuplicatedHeaderParameters(array $header1, array $header2)
    {
        $inter = array_intersect_key($header1, $header2);
        if (!empty($inter)) {
            throw new \InvalidArgumentException(sprintf('The header contains duplicated entries: %s.', implode(', ', array_keys($inter))));
        }
    }
}

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
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Signature\Algorithm\SignatureAlgorithmInterface;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

/**
 * Class able to load JWS and verify signatures and headers.
 */
final class JWSLoader
{
    /**
     * @var AlgorithmManager
     */
    private $signatureAlgorithmManager;

    /**
     * @var HeaderCheckerManager
     */
    private $headerCheckerManager;

    /**
     * @var JWSSerializerManager
     */
    private $serializerManager;

    /**
     * JWSLoader constructor.
     *
     * @param AlgorithmManager     $signatureAlgorithmManager
     * @param HeaderCheckerManager $headerCheckerManager
     * @param JWSSerializerManager $serializerManager
     */
    public function __construct(AlgorithmManager $signatureAlgorithmManager, HeaderCheckerManager $headerCheckerManager, JWSSerializerManager $serializerManager)
    {
        $this->signatureAlgorithmManager = $signatureAlgorithmManager;
        $this->headerCheckerManager = $headerCheckerManager;
        $this->serializerManager = $serializerManager;
    }

    /**
     * @param string      $input
     * @param string|null $serializer
     *
     * @return JWS
     */
    public function load(string $input, ?string &$serializer = null): JWS
    {
        return $this->serializerManager->unserialize($input, $serializer);
    }

    /**
     * @return AlgorithmManager
     */
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->signatureAlgorithmManager;
    }

    /**
     * @param JWS         $jws
     * @param JWK         $jwk
     * @param null|string $detachedPayload
     *
     * @return int If the JWS has been verified, an integer that represents the ID of the signature is set
     */
    public function verifyWithKey(JWS $jws, JWK $jwk, ?string $detachedPayload = null): int
    {
        $jwkset = JWKSet::createFromKeys([$jwk]);

        return $this->verifyWithKeySet($jws, $jwkset, $detachedPayload);
    }

    /**
     * Verify the signature of the input.
     * The input must be a valid JWS. This method is usually called after the "load" method.
     *
     * @param JWS         $jws             A JWS object
     * @param JWKSet      $jwkset          The signature will be verified using keys in the key set
     * @param null|string $detachedPayload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     *
     * @return int If the JWS has been verified, an integer that represents the ID of the signature is set
     */
    public function verifyWithKeySet(JWS $jws, JWKSet $jwkset, ?string $detachedPayload = null): int
    {
        $this->checkJWKSet($jwkset);
        $this->checkSignatures($jws);
        $this->checkPayload($jws, $detachedPayload);

        $nbSignatures = $jws->countSignatures();

        for ($i = 0; $i < $nbSignatures; ++$i) {
            try {
                $this->headerCheckerManager->check($jws, $i);
            } catch (\Exception $e) {
                continue;
            }
            $signature = $jws->getSignature($i);
            if (true === $this->verifySignature($jws, $jwkset, $signature, $detachedPayload)) {
                return $i;
            }
        }

        throw new \InvalidArgumentException('Unable to verify the JWS.');
    }

    /**
     * @param JWS         $jws
     * @param JWKSet      $jwkset
     * @param Signature   $signature
     * @param null|string $detachedPayload
     *
     * @return bool
     */
    private function verifySignature(JWS $jws, JWKSet $jwkset, Signature $signature, ?string $detachedPayload = null): bool
    {
        $input = $this->getInputToVerify($jws, $signature, $detachedPayload);
        foreach ($jwkset->all() as $jwk) {
            $algorithm = $this->getAlgorithm($signature);

            try {
                KeyChecker::checkKeyUsage($jwk, 'verification');
                KeyChecker::checkKeyAlgorithm($jwk, $algorithm->name());
                if (true === $algorithm->verify($jwk, $input, $signature->getSignature())) {
                    return true;
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
        }

        return false;
    }

    /**
     * @param JWS         $jws
     * @param Signature   $signature
     * @param string|null $detachedPayload
     *
     * @return string
     */
    private function getInputToVerify(JWS $jws, Signature $signature, ?string $detachedPayload): string
    {
        $encodedProtectedHeaders = $signature->getEncodedProtectedHeaders();
        if (!$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64')) {
            if (null !== $jws->getEncodedPayload()) {
                return sprintf('%s.%s', $encodedProtectedHeaders, $jws->getEncodedPayload());
            }

            $payload = empty($jws->getPayload()) ? $detachedPayload : $jws->getPayload();

            return sprintf('%s.%s', $encodedProtectedHeaders, Base64Url::encode($payload));
        }

        $payload = empty($jws->getPayload()) ? $detachedPayload : $jws->getPayload();

        return sprintf('%s.%s', $encodedProtectedHeaders, $payload);
    }

    /**
     * @param JWS $jws
     */
    private function checkSignatures(JWS $jws)
    {
        if (0 === $jws->countSignatures()) {
            throw new \InvalidArgumentException('The JWS does not contain any signature.');
        }
    }

    /**
     * @param JWKSet $jwkset
     */
    private function checkJWKSet(JWKSet $jwkset)
    {
        if (0 === count($jwkset)) {
            throw new \InvalidArgumentException('There is no key in the key set.');
        }
    }

    /**
     * @param JWS         $jws
     * @param null|string $detachedPayload
     */
    private function checkPayload(JWS $jws, ?string $detachedPayload = null)
    {
        if (null !== $detachedPayload && !empty($jws->getPayload())) {
            throw new \InvalidArgumentException('A detached payload is set, but the JWS already has a payload.');
        }
        if (empty($jws->getPayload()) && null === $detachedPayload) {
            throw new \InvalidArgumentException('The JWS has a detached payload, but no payload is provided.');
        }
    }

    /**
     * @param Signature $signature
     *
     * @return SignatureAlgorithmInterface
     */
    private function getAlgorithm(Signature $signature): SignatureAlgorithmInterface
    {
        $completeHeaders = array_merge($signature->getProtectedHeaders(), $signature->getHeaders());
        if (!array_key_exists('alg', $completeHeaders)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }

        $algorithm = $this->signatureAlgorithmManager->get($completeHeaders['alg']);
        if (!$algorithm instanceof SignatureAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported or is not a signature algorithm.', $completeHeaders['alg']));
        }

        return $algorithm;
    }
}

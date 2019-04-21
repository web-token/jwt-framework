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

namespace Jose\Component\Signature;

use Base64Url\Base64Url;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

class JWSVerifier
{
    /**
     * @var AlgorithmManager
     */
    private $signatureAlgorithmManager;

    /**
     * JWSVerifier constructor.
     */
    public function __construct(AlgorithmManager $signatureAlgorithmManager)
    {
        $this->signatureAlgorithmManager = $signatureAlgorithmManager;
    }

    /**
     * Returns the algorithm manager associated to the JWSVerifier.
     */
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->signatureAlgorithmManager;
    }

    /**
     * This method will try to verify the JWS object using the given key and for the given signature.
     * It returns true if the signature is verified, otherwise false.
     *
     * @return bool true if the verification of the signature succeeded, else false
     */
    public function verifyWithKey(JWS $jws, JWK $jwk, int $signature, ?string $detachedPayload = null): bool
    {
        $jwkset = new JWKSet([$jwk]);

        return $this->verifyWithKeySet($jws, $jwkset, $signature, $detachedPayload);
    }

    /**
     * This method will try to verify the JWS object using the given key set and for the given signature.
     * It returns true if the signature is verified, otherwise false.
     *
     * @param JWS         $jws             A JWS object
     * @param JWKSet      $jwkset          The signature will be verified using keys in the key set
     * @param string|null $detachedPayload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     *
     * @return bool true if the verification of the signature succeeded, else false
     */
    public function verifyWithKeySet(JWS $jws, JWKSet $jwkset, int $signature, ?string $detachedPayload = null): bool
    {
        $this->checkJWKSet($jwkset);
        $this->checkSignatures($jws);
        $this->checkPayload($jws, $detachedPayload);

        $signature = $jws->getSignature($signature);

        return $this->verifySignature($jws, $jwkset, $signature, $detachedPayload);
    }

    private function verifySignature(JWS $jws, JWKSet $jwkset, Signature $signature, ?string $detachedPayload = null): bool
    {
        $input = $this->getInputToVerify($jws, $signature, $detachedPayload);
        foreach ($jwkset->all() as $jwk) {
            $algorithm = $this->getAlgorithm($signature);

            try {
                KeyChecker::checkKeyUsage($jwk, 'verification');
                KeyChecker::checkKeyAlgorithm($jwk, $algorithm->name());
                if (!\in_array($jwk->get('kty'), $algorithm->allowedKeyTypes(), true)) {
                    throw new \InvalidArgumentException('Wrong key type.');
                }
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

    private function getInputToVerify(JWS $jws, Signature $signature, ?string $detachedPayload): string
    {
        $encodedProtectedHeader = $signature->getEncodedProtectedHeader();
        if (!$signature->hasProtectedHeaderParameter('b64') || true === $signature->getProtectedHeaderParameter('b64')) {
            if (null !== $jws->getEncodedPayload()) {
                return \sprintf('%s.%s', $encodedProtectedHeader, $jws->getEncodedPayload());
            }

            $payload = empty($jws->getPayload()) ? $detachedPayload : $jws->getPayload();

            return \sprintf('%s.%s', $encodedProtectedHeader, Base64Url::encode($payload));
        }

        $payload = empty($jws->getPayload()) ? $detachedPayload : $jws->getPayload();

        return \sprintf('%s.%s', $encodedProtectedHeader, $payload);
    }

    private function checkSignatures(JWS $jws)
    {
        if (0 === $jws->countSignatures()) {
            throw new \InvalidArgumentException('The JWS does not contain any signature.');
        }
    }

    private function checkJWKSet(JWKSet $jwkset)
    {
        if (0 === \count($jwkset)) {
            throw new \InvalidArgumentException('There is no key in the key set.');
        }
    }

    private function checkPayload(JWS $jws, ?string $detachedPayload = null)
    {
        if (null !== $detachedPayload && !empty($jws->getPayload())) {
            throw new \InvalidArgumentException('A detached payload is set, but the JWS already has a payload.');
        }
        if (empty($jws->getPayload()) && null === $detachedPayload) {
            throw new \InvalidArgumentException('The JWS has a detached payload, but no payload is provided.');
        }
    }

    private function getAlgorithm(Signature $signature): SignatureAlgorithm
    {
        $completeHeader = \array_merge($signature->getProtectedHeader(), $signature->getHeader());
        if (!\array_key_exists('alg', $completeHeader)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }

        $algorithm = $this->signatureAlgorithmManager->get($completeHeader['alg']);
        if (!$algorithm instanceof SignatureAlgorithm) {
            throw new \InvalidArgumentException(\sprintf('The algorithm "%s" is not supported or is not a signature algorithm.', $completeHeader['alg']));
        }

        return $algorithm;
    }
}

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

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class JWSLoader
{
    /**
     * @var JWSVerifier
     */
    private $jwsVerifier;

    /**
     * @var HeaderCheckerManager|null
     */
    private $headerCheckerManager;

    /**
     * @var JWSSerializerManager
     */
    private $serializerManager;

    /**
     * JWSLoader constructor.
     *
     * @param JWSSerializerManager      $serializerManager
     * @param JWSVerifier               $jwsVerifier
     * @param HeaderCheckerManager|null $headerCheckerManager
     */
    public function __construct(JWSSerializerManager $serializerManager, JWSVerifier $jwsVerifier, ?HeaderCheckerManager $headerCheckerManager)
    {
        $this->serializerManager = $serializerManager;
        $this->jwsVerifier = $jwsVerifier;
        $this->headerCheckerManager = $headerCheckerManager;
    }

    /**
     * Returns the JWSVerifier associated to the JWSLoader.
     *
     * @return JWSVerifier
     */
    public function getJwsVerifier(): JWSVerifier
    {
        return $this->jwsVerifier;
    }

    /**
     * Returns the Header Checker Manager associated to the JWSLoader.
     *
     * @return HeaderCheckerManager|null
     */
    public function getHeaderCheckerManager(): ?HeaderCheckerManager
    {
        return $this->headerCheckerManager;
    }

    /**
     * Returns the JWSSerializer associated to the JWSLoader.
     *
     * @return JWSSerializerManager
     */
    public function getSerializerManager(): JWSSerializerManager
    {
        return $this->serializerManager;
    }

    /**
     * This method will try to load and verify the token using the given key.
     * It returns a JWS and will populate the $signature variable in case of success, otherwise an exception is thrown.
     *
     * @param string      $token
     * @param JWK         $key
     * @param null|int    $signature
     * @param null|string $payload
     *
     * @throws \Exception
     *
     * @return JWS
     */
    public function loadAndVerifyWithKey(string $token, JWK $key, ?int &$signature, ?string $payload = null): JWS
    {
        $keyset = JWKSet::createFromKeys([$key]);

        return $this->loadAndVerifyWithKeySet($token, $keyset, $signature, $payload);
    }

    /**
     * This method will try to load and verify the token using the given key set.
     * It returns a JWS and will populate the $signature variable in case of success, otherwise an exception is thrown.
     *
     * @param string      $token
     * @param JWKSet      $keyset
     * @param null|int    $signature
     * @param null|string $payload
     *
     * @throws \Exception
     *
     * @return JWS
     */
    public function loadAndVerifyWithKeySet(string $token, JWKSet $keyset, ?int &$signature, ?string $payload = null): JWS
    {
        try {
            $jws = $this->serializerManager->unserialize($token);
            $nbSignatures = $jws->countSignatures();
            for ($i = 0; $i < $nbSignatures; $i++) {
                if ($this->processSignature($jws, $keyset, $i, $payload)) {
                    $signature = $i;

                    return $jws;
                }
            }
        } catch (\Exception $e) {
            // Nothing to do. Exception thrown just after
        }

        throw new \Exception('Unable to load and verify the token.');
    }

    /**
     * @param JWS         $jws
     * @param JWKSet      $keyset
     * @param int         $signature
     * @param null|string $payload
     *
     * @return bool
     */
    private function processSignature(JWS $jws, JWKSet $keyset, int $signature, ?string $payload): bool
    {
        try {
            if (null !== $this->headerCheckerManager) {
                $this->headerCheckerManager->check($jws, $signature);
            }

            return $this->jwsVerifier->verifyWithKeySet($jws, $keyset, $signature, $payload);
        } catch (\Exception $e) {
            return false;
        }
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

/**
 * Loads a serialized JWS, checks its header and verifies its signatures.
 *
 * The interface is implemented by JWSLoader and by every object that decorates it. Decoration is the supported way of
 * plugging behaviour into the loader: JWSLoader is annotated as final and will be final in 5.0.0.
 */
interface JWSLoaderInterface
{
    /**
     * Returns the verifier associated to the loader.
     */
    public function getJwsVerifier(): JWSVerifierInterface;

    /**
     * Returns the header checker manager associated to the loader, if any.
     */
    public function getHeaderCheckerManager(): ?HeaderCheckerManagerInterface;

    /**
     * Returns the serializer manager associated to the loader.
     */
    public function getSerializerManager(): JWSSerializerManager;

    /**
     * Loads and verifies the token using the given key. It returns a JWS and populates the $signature variable in case
     * of success, otherwise an exception is thrown.
     */
    public function loadAndVerifyWithKey(string $token, JWK $key, ?int &$signature, ?string $payload = null): JWS;

    /**
     * Loads and verifies the token using the given key set. It returns a JWS and populates the $signature variable in
     * case of success, otherwise an exception is thrown.
     */
    public function loadAndVerifyWithKeySet(
        string $token,
        JWKSet $keyset,
        ?int &$signature,
        ?string $payload = null
    ): JWS;
}

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
 *
 * The interface only declares the methods that will survive 5.0.0. "loadAndVerifyWithKey()" and
 * "loadAndVerifyWithKeySet()", deprecated since 4.3.0 because they write the index of the verified signature into a
 * variable of the caller, are still available on JWSLoader and on the objects of this package that decorate it, but
 * they are not part of the contract.
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
     * Loads and verifies the token using the given key or key set. The JWS, the index of the verified signature and
     * the key that verified it are carried by the returned result, otherwise an exception is thrown.
     *
     * @param JWK|JWKSet $keys The signature will be verified using that key or the keys in that key set
     * @param string|null $payload If not null, the value must be the detached payload encoded in Base64 URL safe
     */
    public function loadAndVerify(string $token, JWK|JWKSet $keys, ?string $payload = null): LoadingResult;
}

<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Throwable;

/**
 * Verifies the signatures of a JWS.
 *
 * The interface is implemented by JWSVerifier and by every object that decorates it. Decoration is the supported way
 * of plugging behaviour into the verifier: JWSVerifier is annotated as final and will be final in 5.0.0.
 *
 * The interface only declares the methods that will survive 5.0.0. "verifyWithKeySet()", deprecated since 4.3.0
 * because it writes the key it used into a variable of the caller, is still available on JWSVerifier and on the
 * objects of this package that decorate it, but it is not part of the contract.
 */
interface JWSVerifierInterface
{
    /**
     * Returns the algorithm manager associated to the verifier.
     */
    public function getSignatureAlgorithmManager(): AlgorithmManager;

    /**
     * Verifies the given signature of the JWS object using the given key.
     *
     * @return bool true if the verification of the signature succeeded, else false
     */
    public function verifyWithKey(JWS $jws, JWK $jwk, int $signature, ?string $detachedPayload = null): bool;

    /**
     * Verifies the given signature of the JWS object using the given key or key set. The key that verified the
     * signature is carried by the returned result.
     *
     * A key that cannot be used, or that does not verify the signature, does not abort the verification: the next key
     * of the key set is tried and the reason of the failure is otherwise lost. The optional callable is called with
     * every discarded Throwable, so that those failures can be observed.
     *
     * @param JWK|JWKSet $keys The signature will be verified using that key or the keys in that key set
     * @param string|null $detachedPayload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     * @param (callable(Throwable): void)|null $onError Called with every failure met while trying the keys
     */
    public function verify(
        JWS $jws,
        JWK|JWKSet $keys,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?callable $onError = null
    ): VerificationResult;
}

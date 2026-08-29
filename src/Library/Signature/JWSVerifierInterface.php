<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * Verifies the signatures of a JWS.
 *
 * The interface is implemented by JWSVerifier and by every object that decorates it. Decoration is the supported way
 * of plugging behaviour into the verifier: JWSVerifier is annotated as final and will be final in 5.0.0.
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
     * Verifies the given signature of the JWS object using the given key set.
     *
     * A key that cannot be used, or that does not verify the signature, does not abort the verification: the next key
     * of the key set is tried and the reason of the failure is otherwise lost. A callable is accepted as an additional
     * argument to observe those failures; it is called with every discarded Throwable. That argument is not part of
     * the signature yet - it will be in 5.0.0 - and is read with func_num_args()/func_get_arg(5). An implementation
     * that does not read it still behaves correctly, it only loses the reason of the failures.
     *
     * @param string|null $detachedPayload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     * @param JWK|null $jwk The key used to verify the signature in case of success
     *
     * @return bool true if the verification of the signature succeeded, else false
     */
    public function verifyWithKeySet(
        JWS $jws,
        JWKSet $jwkset,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?JWK &$jwk = null
    ): bool;
}

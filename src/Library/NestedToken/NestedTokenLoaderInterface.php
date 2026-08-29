<?php

declare(strict_types=1);

namespace Jose\Component\NestedToken;

use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\LoadingResult;

/**
 * Loads a nested token: a JWS serialized as the payload of a JWE.
 *
 * The interface is implemented by NestedTokenLoader and by every object that decorates it. Decoration is the supported
 * way of plugging behaviour into the loader: NestedTokenLoader is annotated as final and will be final in 5.0.0.
 */
interface NestedTokenLoaderInterface
{
    /**
     * Loads, decrypts and verifies the token. In case of failure, an exception is thrown, otherwise the JWS, the index
     * of the verified signature and the key that verified it are carried by the returned result.
     */
    public function loadAndVerify(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet): LoadingResult;

    /**
     * Loads, decrypts and verifies the token. In case of failure, an exception is thrown, otherwise the JWS is returned
     * and the $signature variable is populated.
     *
     * @param int|null $signature the index of the verified signature. Passing that argument is deprecated since 4.3.0
     *                            and it will be removed in 5.0.0: use "loadAndVerify()" instead.
     *
     * @param-out int $signature
     */
    public function load(
        string $token,
        JWKSet $encryptionKeySet,
        JWKSet $signatureKeySet,
        ?int &$signature = null
    ): JWS;
}

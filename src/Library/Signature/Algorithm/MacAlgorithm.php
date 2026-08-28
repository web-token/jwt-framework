<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;

/**
 * A MAC algorithm is a signature algorithm: it produces a signature from a key and an input, and verifies it.
 *
 * The interface only exists to tell symmetric algorithms apart from the asymmetric ones, for key selection or policy
 * decisions. Since 4.3.0 every MAC algorithm shipped by the library also implements SignatureAlgorithm, and sign() is
 * the method to call. Implement both interfaces to be ready for 5.0.0, where MacAlgorithm will extend
 * SignatureAlgorithm and hash() will be removed.
 */
interface MacAlgorithm extends Algorithm
{
    /**
     * Sign the input.
     *
     * @deprecated since 4.3.0, use SignatureAlgorithm::sign() instead. Will be removed in 5.0.0.
     *
     * @param JWK $key The private key used to hash the data
     * @param string $input The input
     */
    public function hash(JWK $key, string $input): string;

    /**
     * Verify the signature of data.
     *
     * @param JWK $key The private key used to hash the data
     * @param string $input The input
     * @param string $signature The signature to verify
     */
    public function verify(JWK $key, string $input, string $signature): bool;
}

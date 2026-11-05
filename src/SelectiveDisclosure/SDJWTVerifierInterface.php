<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * Verifies SD-JWTs and returns their Processed SD-JWT Payload: the Verifier role of RFC 9901, and the checks a Holder
 * makes on the SD-JWT it receives.
 *
 * Whether Key Binding is required is decided by the caller, by calling one method or the other, and never by the token
 * (section 7.3 step 1): verify() rejects an SD-JWT+KB and verifyWithKeyBinding() rejects an SD-JWT, so that a Key
 * Binding JWT can neither be stripped nor be added without the presentation being rejected.
 *
 * The interface is implemented by SDJWTVerifier and by every object that decorates it. Decoration is the supported way
 * of plugging behaviour into the Verifier: SDJWTVerifier is final.
 */
interface SDJWTVerifierInterface
{
    /**
     * Verifies an SD-JWT without Key Binding (section 7.1), as a Holder receiving it from the Issuer does, or as a
     * Verifier that does not require Key Binding does.
     *
     * @param JWK|JWKSet $issuerKeys the key or the key set of the Issuer
     */
    public function verify(string $sdJwt, JWK|JWKSet $issuerKeys): VerifiedSDJWT;

    /**
     * Verifies an SD-JWT+KB (section 7.3): the SD-JWT as verify() does, then its Key Binding JWT against the key of the
     * "cnf" claim, the given audience and nonce, and the presented Disclosures.
     *
     * @param JWK|JWKSet $issuerKeys the key or the key set of the Issuer
     * @param string $audience the identifier of the Verifier, the expected "aud" claim
     * @param string $nonce the nonce of the transaction, the expected "nonce" claim
     */
    public function verifyWithKeyBinding(
        string $sdJwt,
        JWK|JWKSet $issuerKeys,
        string $audience,
        string $nonce
    ): VerifiedSDJWT;
}

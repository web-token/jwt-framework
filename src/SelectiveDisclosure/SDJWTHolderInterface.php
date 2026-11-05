<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\JWK;

/**
 * Presents SD-JWTs with a Key Binding JWT: the Holder role of RFC 9901.
 *
 * The Holder selects the Disclosures of a presentation with SDJWT::select(). When the Verifier does not require Key
 * Binding, that SD-JWT is the presentation; otherwise this interface ties it to the holder key.
 *
 * The interface is implemented by SDJWTHolder and by every object that decorates it. Decoration is the supported way
 * of plugging behaviour into the Holder: SDJWTHolder is final.
 */
interface SDJWTHolderInterface
{
    /**
     * Creates the Key Binding JWT of the given SD-JWT and returns the SD-JWT+KB to send to the Verifier (section 7.2).
     *
     * The protected header must name a signature algorithm in "alg"; its "typ" is "kb+jwt". The key must be the
     * private key of the public key the SD-JWT carries in its "cnf" claim.
     *
     * @param array<string, mixed> $protectedHeader
     * @param string $audience the identifier of the Verifier, the "aud" claim
     * @param string $nonce the value that ties the presentation to the transaction, the "nonce" claim
     */
    public function present(
        SDJWT $sdJwt,
        JWK $holderKey,
        array $protectedHeader,
        string $audience,
        string $nonce
    ): SDJWT;
}

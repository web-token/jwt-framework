<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\JWK;

/**
 * Issues SD-JWTs: the Issuer role of RFC 9901.
 *
 * The interface is implemented by SDJWTIssuer and by every object that decorates it. Decoration is the supported way
 * of plugging behaviour into the Issuer: SDJWTIssuer is final.
 */
interface SDJWTIssuerInterface
{
    /**
     * Issues an SD-JWT with all its Disclosures, as it is handed to the Holder.
     *
     * The values that are selectively disclosable are wrapped in a Disclosable. The Issuer-signed JWT is signed with
     * the given key and protected header, which must name a signature algorithm in "alg"; RFC 9901 recommends an
     * explicit "typ", such as "example+sd-jwt" (section 9.11).
     *
     * @param array<mixed> $claims the claims, a JSON object
     * @param array<string, mixed> $protectedHeader
     */
    public function issue(array $claims, JWK $signatureKey, array $protectedHeader): SDJWT;

    /**
     * Issues an SD-JWT in the JWS JSON serialization (RFC 9901 section 8), with all its Disclosures: in the flattened
     * serialization with one signature, in the general one with several.
     *
     * The claims are processed as by issue(). The Issuer-signed JWT is signed once for each given signature, whose
     * protected header must name a signature algorithm in "alg". The Disclosures are carried by the "disclosures"
     * parameter of the unprotected header of the first signature.
     *
     * @param array<mixed> $claims the claims, a JSON object
     */
    public function issueJson(array $claims, IssuerSignature $signature, IssuerSignature ...$signatures): SDJWT;
}

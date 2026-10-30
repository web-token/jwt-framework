<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerInterface;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Checker\TypeChecker;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\NamedInformationHash;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoaderInterface;
use Override;
use Psr\Clock\ClockInterface;
use Throwable;
use function array_is_list;
use function array_key_exists;
use function hash_equals;
use function in_array;
use function is_array;
use function is_float;
use function is_int;
use function is_string;
use function sprintf;

/**
 * Verifies SD-JWTs and SD-JWT+KBs, as RFC 9901 sections 7.1 and 7.3 describe.
 *
 * The Issuer-signed JWT is loaded by the given loader, whose serializers, algorithms and header checkers apply: the
 * "typ" of the application profile (section 9.11) and the accepted signature algorithms are checked there. Whatever
 * the loader accepts, the Issuer-signed JWT and the Key Binding JWT must be signed with a digital signature algorithm,
 * not with a MAC. The
 * Disclosures are then processed with the rules of section 7.1, the hash algorithm declared by "_sd_alg" being one of
 * the accepted ones. The processed payload is finally checked by the claim checker manager, if any, with the mandatory
 * claims: the claims that control the validity of the SD-JWT may be selectively disclosable, and are only present
 * once disclosed (section 9.7).
 *
 * The Key Binding JWT is loaded by its own loader, with the key of the "cnf" claim of the processed payload, whose
 * "jwk" confirmation method is the one supported (section 4.1.2). Its type must be "kb+jwt", compared by the
 * TypeChecker of the library (case-insensitively, the "application/" prefix being optional), its "iat" no older than
 * the given maximum age and not in the future, both with the allowed time drift, its "aud" and "nonce" the expected
 * ones, its "sd_hash" the digest of the presented SD-JWT, and its "exp" and "nbf", if any, valid.
 *
 * Every rejection is reported by an InvalidTokenException, whose previous exception, if any, gives the cause.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-7
 */
final readonly class SDJWTVerifier implements SDJWTVerifierInterface
{
    /**
     * @var list<string>
     */
    private array $hashAlgorithms;

    /**
     * @param JWSLoaderInterface $issuerSignedJwtLoader the loader of the Issuer-signed JWTs
     * @param ClockInterface $clock the clock the creation time of the Key Binding JWTs is compared to
     * @param JWSLoaderInterface|null $keyBindingJwtLoader the loader of the Key Binding JWTs; without it, Key Binding
     *                                                     cannot be verified
     * @param ClaimCheckerManagerInterface|null $claimCheckerManager checks the processed payload
     * @param list<string> $mandatoryClaims the claims the processed payload must contain
     * @param list<string>|null $hashAlgorithms the IANA names of the accepted hash functions, all the supported ones
     *                                          when null
     * @param int $keyBindingMaxAge the maximum age of a Key Binding JWT, in seconds
     * @param int $allowedTimeDrift the drift allowed between the clocks, in seconds
     *
     * @throws UnsupportedAlgorithmException if an accepted hash function is not supported
     * @throws InvalidArgumentException if the maximum age or the time drift is negative
     */
    public function __construct(
        private JWSLoaderInterface $issuerSignedJwtLoader,
        private ClockInterface $clock,
        private ?JWSLoaderInterface $keyBindingJwtLoader = null,
        private ?ClaimCheckerManagerInterface $claimCheckerManager = null,
        private array $mandatoryClaims = [],
        ?array $hashAlgorithms = null,
        private int $keyBindingMaxAge = 300,
        private int $allowedTimeDrift = 0
    ) {
        $accepted = [];
        foreach ($hashAlgorithms ?? NamedInformationHash::names() as $hashAlgorithm) {
            NamedInformationHash::phpName($hashAlgorithm);
            $accepted[] = $hashAlgorithm;
        }
        if ($keyBindingMaxAge < 0 || $allowedTimeDrift < 0) {
            throw new InvalidArgumentException(
                'The maximum age of the Key Binding JWT and the allowed time drift must be non-negative.'
            );
        }
        $this->hashAlgorithms = $accepted;
    }

    #[Override]
    public function verify(string $sdJwt, JWK|JWKSet $issuerKeys): VerifiedSDJWT
    {
        $parsed = self::parse($sdJwt);
        if ($parsed->hasKeyBinding()) {
            throw new InvalidTokenException('A Key Binding JWT is not expected.');
        }
        [$issuerSignedJwt, $issuerKey, $claims] = $this->process($parsed, $issuerKeys);

        return new VerifiedSDJWT($parsed, $claims, $issuerSignedJwt, $issuerKey);
    }

    #[Override]
    public function verifyWithKeyBinding(
        string $sdJwt,
        JWK|JWKSet $issuerKeys,
        string $audience,
        string $nonce
    ): VerifiedSDJWT {
        if ($this->keyBindingJwtLoader === null) {
            throw new LogicException(
                'No loader is configured for the Key Binding JWT: key binding cannot be verified.'
            );
        }
        $parsed = self::parse($sdJwt);
        $keyBindingJwt = $parsed->getKeyBindingJwt();
        if ($keyBindingJwt === null) {
            throw new InvalidTokenException('A Key Binding JWT is required.');
        }
        [$issuerSignedJwt, $issuerKey, $claims] = $this->process($parsed, $issuerKeys);
        $holderKey = self::holderKey($claims);
        try {
            $loaded = $this->keyBindingJwtLoader->loadAndVerify($keyBindingJwt, $holderKey)
                ->getJws();
        } catch (Throwable $throwable) {
            throw new InvalidTokenException('The Key Binding JWT cannot be verified.', 0, $throwable);
        }
        self::checkSignatureAlgorithm($this->keyBindingJwtLoader, $loaded, 'Key Binding JWT');
        $this->checkKeyBindingJwt($loaded, $parsed, $audience, $nonce);

        return new VerifiedSDJWT($parsed, $claims, $issuerSignedJwt, $issuerKey, $loaded, $holderKey);
    }

    private static function parse(string $sdJwt): SDJWT
    {
        try {
            return SDJWT::fromString($sdJwt);
        } catch (Throwable $throwable) {
            throw new InvalidTokenException('The SD-JWT cannot be parsed.', 0, $throwable);
        }
    }

    /**
     * Verifies the Issuer-signed JWT, processes the Disclosures and checks the processed payload.
     *
     * @return array{JWS, JWK, array<string, mixed>}
     */
    private function process(SDJWT $sdJwt, JWK|JWKSet $issuerKeys): array
    {
        try {
            $loaded = $this->issuerSignedJwtLoader->loadAndVerify($sdJwt->getIssuerSignedJwt(), $issuerKeys);
        } catch (Throwable $throwable) {
            throw new InvalidTokenException('The Issuer-signed JWT cannot be verified.', 0, $throwable);
        }
        self::checkSignatureAlgorithm($this->issuerSignedJwtLoader, $loaded->getJws(), 'Issuer-signed JWT');
        $payload = self::payload($loaded->getJws(), 'Issuer-signed JWT');
        $hashAlgorithm = DisclosureProcessor::declaredHashAlgorithm($payload);
        if (! in_array($hashAlgorithm, $this->hashAlgorithms, true)) {
            throw new InvalidTokenException(sprintf(
                'The hash algorithm "%s" of the SD-JWT is not accepted.',
                $hashAlgorithm
            ));
        }
        $claims = DisclosureProcessor::process($payload, $sdJwt->getDisclosures(), $hashAlgorithm)['claims'];
        try {
            ($this->claimCheckerManager ?? new ClaimCheckerManager([]))->check($claims, $this->mandatoryClaims);
        } catch (Throwable $throwable) {
            throw new InvalidTokenException('The claims of the SD-JWT are not valid.', 0, $throwable);
        }

        return [$loaded->getJws(), $loaded->getKey(), $claims];
    }

    /**
     * Checks the type and the claims of the Key Binding JWT once its signature is verified (section 7.3 steps 5.d to
     * 5.h).
     */
    private function checkKeyBindingJwt(JWS $keyBindingJwt, SDJWT $sdJwt, string $audience, string $nonce): void
    {
        try {
            (new TypeChecker([SDJWT::KEY_BINDING_JWT_TYPE]))->checkHeader(
                $keyBindingJwt->getSignature(0)->getProtectedHeader()['typ'] ?? null
            );
        } catch (InvalidHeaderException $exception) {
            throw new InvalidTokenException('The Key Binding JWT must be of type "kb+jwt".', 0, $exception);
        }
        $claims = self::payload($keyBindingJwt, 'Key Binding JWT');
        $issuedAt = $claims['iat'] ?? null;
        if (! is_int($issuedAt) && ! is_float($issuedAt)) {
            throw new InvalidTokenException('The "iat" claim of the Key Binding JWT must be a number.');
        }
        $now = $this->clock->now()
            ->getTimestamp();
        if ($issuedAt > $now + $this->allowedTimeDrift) {
            throw new InvalidTokenException('The Key Binding JWT is issued in the future.');
        }
        if ($issuedAt < $now - $this->keyBindingMaxAge - $this->allowedTimeDrift) {
            throw new InvalidTokenException('The Key Binding JWT is too old.');
        }
        if (self::stringClaim($claims, 'aud') !== $audience) {
            throw new InvalidTokenException('The Key Binding JWT is not intended for this audience.');
        }
        if (! hash_equals($nonce, self::stringClaim($claims, 'nonce'))) {
            throw new InvalidTokenException('The nonce of the Key Binding JWT does not match.');
        }
        if (! hash_equals($sdJwt->getSdHash(), self::stringClaim($claims, 'sd_hash'))) {
            throw new InvalidTokenException('The Key Binding JWT is not bound to the SD-JWT.');
        }
        try {
            if (array_key_exists('exp', $claims)) {
                (new ExpirationTimeChecker($this->clock, $this->allowedTimeDrift))->checkClaim($claims['exp']);
            }
            if (array_key_exists('nbf', $claims)) {
                (new NotBeforeChecker($this->clock, $this->allowedTimeDrift))->checkClaim($claims['nbf']);
            }
        } catch (Throwable $throwable) {
            throw new InvalidTokenException('The Key Binding JWT is not valid.', 0, $throwable);
        }
    }

    /**
     * Checks that the token is signed with a digital signature algorithm: the Issuer-signed JWT is signed with the
     * private key of the Issuer (section 4.1) and the Key Binding JWT with the private key of the Holder (section 4.3),
     * which a MAC algorithm, whose key is shared, cannot prove. The "none" algorithm has an empty signature, which the
     * format of the SD-JWT already refuses.
     */
    private static function checkSignatureAlgorithm(JWSLoaderInterface $loader, JWS $jws, string $token): void
    {
        $algorithm = $jws->getSignature(0)
            ->getProtectedHeaderParameter('alg');
        $algorithmManager = $loader->getJwsVerifier()
            ->getSignatureAlgorithmManager();
        if (! is_string($algorithm) || ! $algorithmManager->get($algorithm) instanceof SignatureAlgorithm) {
            throw new InvalidTokenException(sprintf(
                'The %s must be signed with a digital signature algorithm.',
                $token
            ));
        }
    }

    /**
     * Reads the holder key from the "cnf" claim of the processed payload. Only the "jwk" confirmation method of RFC
     * 7800 is supported: the other ones reference a key the Verifier would have to resolve.
     *
     * @param array<mixed> $claims
     */
    private static function holderKey(array $claims): JWK
    {
        $confirmation = $claims['cnf'] ?? null;
        if (! is_array($confirmation) || ! is_array($confirmation['jwk'] ?? null)) {
            throw new InvalidTokenException(
                'The holder key cannot be determined: the SD-JWT has no "cnf" claim with a "jwk" member.'
            );
        }
        try {
            return new JWK($confirmation['jwk']);
        } catch (Throwable $throwable) {
            throw new InvalidTokenException('The JWK of the "cnf" claim is not valid.', 0, $throwable);
        }
    }

    /**
     * @return array<mixed>
     */
    private static function payload(JWS $jws, string $token): array
    {
        $message = sprintf('The payload of the %s must be a JSON object.', $token);
        try {
            $payload = JsonConverter::decode((string) $jws->getPayload());
        } catch (Throwable $throwable) {
            throw new InvalidTokenException($message, 0, $throwable);
        }
        if (! is_array($payload) || ($payload !== [] && array_is_list($payload))) {
            throw new InvalidTokenException($message);
        }

        return $payload;
    }

    /**
     * @param array<mixed> $claims
     */
    private static function stringClaim(array $claims, string $name): string
    {
        $value = $claims[$name] ?? null;
        if (! is_string($value)) {
            throw new InvalidTokenException(sprintf(
                'The "%s" claim of the Key Binding JWT must be a string.',
                $name
            ));
        }

        return $value;
    }
}

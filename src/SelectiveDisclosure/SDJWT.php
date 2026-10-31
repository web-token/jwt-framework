<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\NamedInformationHash;
use Override;
use Stringable;
use Throwable;
use function array_is_list;
use function explode;
use function is_array;
use function preg_match;
use function sprintf;
use function strpos;
use function substr;

/**
 * An SD-JWT, or an SD-JWT+KB, in the compact format of RFC 9901 section 4: the Issuer-signed JWT and a tilde, each
 * Disclosure followed by a tilde, then the Key Binding JWT, if any.
 *
 *     <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<optional Key Binding JWT>
 *
 * It is what the Issuer returns, what the Holder stores, selects Disclosures from and presents, and what the Verifier
 * parses. The object verifies nothing: the claims it reads from the Issuer-signed JWT, for the hash algorithm and for
 * the selection, are not authenticated until the token is verified by an SDJWTVerifierInterface.
 *
 * The parts are kept as they were given, so that the string representation of a parsed SD-JWT is the parsed string:
 * the "sd_hash" claim of a Key Binding JWT is computed over those exact bytes.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-4
 */
final readonly class SDJWT implements Stringable
{
    /**
     * The hash algorithm of an SD-JWT without "_sd_alg" claim (section 4.1.1).
     */
    public const DEFAULT_HASH_ALGORITHM = 'sha-256';

    /**
     * The type of the Key Binding JWTs, their "typ" header parameter (section 4.3).
     */
    public const KEY_BINDING_JWT_TYPE = 'kb+jwt';

    /**
     * A JWS in compact serialization whose three parts are not empty, as the ABNF of section 4 requires.
     */
    private const COMPACT_JWS = '/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/';

    /**
     * @param list<Disclosure> $disclosures
     */
    private function __construct(
        private string $issuerSignedJwt,
        private array $disclosures,
        private ?string $keyBindingJwt
    ) {
    }

    /**
     * @param list<Disclosure> $disclosures
     *
     * @throws InvalidSerializationException if a JWT is not a JWS in compact serialization
     */
    public static function create(string $issuerSignedJwt, array $disclosures = [], ?string $keyBindingJwt = null): self
    {
        self::checkIssuerSignedJwt($issuerSignedJwt);
        if ($keyBindingJwt !== null) {
            self::checkKeyBindingJwt($keyBindingJwt);
        }

        return new self($issuerSignedJwt, $disclosures, $keyBindingJwt);
    }

    /**
     * Parses an SD-JWT or an SD-JWT+KB. The parts are checked one after the other while the string is read, so that a
     * malformed input is rejected as soon as the malformed part is met.
     *
     * @throws InvalidSerializationException if the string is not an SD-JWT
     */
    public static function fromString(string $sdJwt): self
    {
        $separator = strpos($sdJwt, '~');
        if ($separator === false) {
            throw new InvalidSerializationException(
                'The SD-JWT must contain a "~" separator after the Issuer-signed JWT.'
            );
        }
        $issuerSignedJwt = substr($sdJwt, 0, $separator);
        self::checkIssuerSignedJwt($issuerSignedJwt);
        $disclosures = [];
        $offset = $separator + 1;
        while (($separator = strpos($sdJwt, '~', $offset)) !== false) {
            if ($separator === $offset) {
                throw new InvalidSerializationException('A Disclosure of the SD-JWT is empty.');
            }
            $disclosures[] = Disclosure::fromString(substr($sdJwt, $offset, $separator - $offset));
            $offset = $separator + 1;
        }
        $keyBindingJwt = substr($sdJwt, $offset);
        if ($keyBindingJwt === '') {
            return new self($issuerSignedJwt, $disclosures, null);
        }
        self::checkKeyBindingJwt($keyBindingJwt);

        return new self($issuerSignedJwt, $disclosures, $keyBindingJwt);
    }

    /**
     * Lists the hash functions the digests can be computed with, by their IANA name: the values of "_sd_alg" this
     * library supports.
     *
     * @return list<non-empty-string>
     */
    public static function hashAlgorithms(): array
    {
        return NamedInformationHash::names();
    }

    public function getIssuerSignedJwt(): string
    {
        return $this->issuerSignedJwt;
    }

    /**
     * @return list<Disclosure>
     */
    public function getDisclosures(): array
    {
        return $this->disclosures;
    }

    public function getKeyBindingJwt(): ?string
    {
        return $this->keyBindingJwt;
    }

    public function hasKeyBinding(): bool
    {
        return $this->keyBindingJwt !== null;
    }

    /**
     * Returns the SD-JWT+KB made of this SD-JWT and the given Key Binding JWT.
     *
     * @throws LogicException if the SD-JWT already has a Key Binding JWT
     */
    public function withKeyBindingJwt(string $keyBindingJwt): self
    {
        if ($this->keyBindingJwt !== null) {
            throw new LogicException('The SD-JWT already has a Key Binding JWT.');
        }
        self::checkKeyBindingJwt($keyBindingJwt);

        return new self($this->issuerSignedJwt, $this->disclosures, $keyBindingJwt);
    }

    public function withoutKeyBinding(): self
    {
        return new self($this->issuerSignedJwt, $this->disclosures, null);
    }

    /**
     * The IANA name of the hash function of the digests, read from the "_sd_alg" claim of the Issuer-signed JWT.
     *
     * @throws InvalidTokenException if the payload of the Issuer-signed JWT cannot be read
     * @throws UnsupportedAlgorithmException if the hash function is not supported
     */
    public function getHashAlgorithm(): string
    {
        $hashAlgorithm = DisclosureProcessor::declaredHashAlgorithm($this->payload());
        NamedInformationHash::phpName($hashAlgorithm);

        return $hashAlgorithm;
    }

    /**
     * The value of the "sd_hash" claim of a Key Binding JWT tied to this SD-JWT (section 4.3.1): the base64url-encoded
     * digest of the Issuer-signed JWT and of the Disclosures, each followed by a tilde, computed with the hash
     * function of the SD-JWT.
     */
    public function getSdHash(): string
    {
        return Base64UrlSafe::encodeUnpadded(
            NamedInformationHash::hash($this->getHashAlgorithm(), $this->withoutKeyBinding()->toString())
        );
    }

    /**
     * Returns the SD-JWT with the Disclosures needed to disclose the claims designated by the given claim paths, for a
     * presentation (section 7.2).
     *
     * The Disclosures of a claim come with the Disclosures of the objects and arrays that contain it, without which
     * the claim could not be inserted (section 4.2.6), and with the Disclosures it contains: selecting an object
     * discloses all of it. The Disclosures keep the order they have in this SD-JWT. A claim that is not selectively
     * disclosable needs no Disclosure. A path that designates no claim is refused, so that a mistyped name does not
     * silently disclose less than intended.
     *
     * See ClaimPath for the syntax of the paths. The Issuer-signed JWT is not verified here.
     *
     * @param array<mixed> ...$claimPaths
     *
     * @throws LogicException if the SD-JWT has a Key Binding JWT
     * @throws InvalidArgumentException if a claim path is malformed or designates no claim
     * @throws InvalidTokenException if the Disclosures cannot be processed
     */
    public function select(array ...$claimPaths): self
    {
        if ($this->keyBindingJwt !== null) {
            throw new LogicException('The Disclosures of an SD-JWT with a Key Binding JWT cannot be selected.');
        }
        foreach ($claimPaths as $claimPath) {
            ClaimPath::check($claimPath);
        }
        $hashAlgorithm = $this->getHashAlgorithm();
        $processed = DisclosureProcessor::process($this->payload(), $this->disclosures, $hashAlgorithm);
        foreach ($claimPaths as $claimPath) {
            if (! ClaimPath::matches($processed['claims'], $claimPath)) {
                throw new InvalidArgumentException(sprintf(
                    'The claim path %s does not match any claim.',
                    JsonConverter::encode($claimPath)
                ));
            }
        }
        $selected = [];
        foreach ($this->disclosures as $disclosure) {
            $disclosurePath = $processed['paths'][$disclosure->digest($hashAlgorithm)];
            foreach ($claimPaths as $claimPath) {
                if (ClaimPath::overlaps($claimPath, $disclosurePath)) {
                    $selected[] = $disclosure;
                    break;
                }
            }
        }

        return new self($this->issuerSignedJwt, $selected, null);
    }

    public function toString(): string
    {
        $sdJwt = $this->issuerSignedJwt . '~';
        foreach ($this->disclosures as $disclosure) {
            $sdJwt .= $disclosure->toString() . '~';
        }

        return $sdJwt . $this->keyBindingJwt;
    }

    #[Override]
    public function __toString(): string
    {
        return $this->toString();
    }

    private static function checkIssuerSignedJwt(string $issuerSignedJwt): void
    {
        if (preg_match(self::COMPACT_JWS, $issuerSignedJwt) !== 1) {
            throw new InvalidSerializationException('The Issuer-signed JWT must be a JWS in compact serialization.');
        }
    }

    private static function checkKeyBindingJwt(string $keyBindingJwt): void
    {
        if (preg_match(self::COMPACT_JWS, $keyBindingJwt) !== 1) {
            throw new InvalidSerializationException('The Key Binding JWT must be a JWS in compact serialization.');
        }
    }

    /**
     * Decodes the payload of the Issuer-signed JWT, without verifying its signature.
     *
     * @return array<mixed>
     */
    private function payload(): array
    {
        try {
            $payload = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(explode('.', $this->issuerSignedJwt)[1]));
        } catch (Throwable $throwable) {
            throw new InvalidTokenException('The payload of the Issuer-signed JWT cannot be decoded.', 0, $throwable);
        }
        if (! is_array($payload) || ($payload !== [] && array_is_list($payload))) {
            throw new InvalidTokenException('The payload of the Issuer-signed JWT must be a JSON object.');
        }

        return $payload;
    }
}

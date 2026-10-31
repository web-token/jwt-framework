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
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Override;
use Stringable;
use Throwable;
use function array_is_list;
use function array_key_exists;
use function array_key_first;
use function array_map;
use function explode;
use function is_array;
use function is_string;
use function ltrim;
use function preg_match;
use function sprintf;
use function str_starts_with;
use function strpos;
use function substr;

/**
 * An SD-JWT, or an SD-JWT+KB, in the compact format of RFC 9901 section 4 or in the JWS JSON serialization of
 * section 8.
 *
 * The compact format is the Issuer-signed JWT and a tilde, each Disclosure followed by a tilde, then the Key Binding
 * JWT, if any:
 *
 *     <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<optional Key Binding JWT>
 *
 * In the JWS JSON serialization, the Issuer-signed JWT is a JWS in the flattened or the general JSON serialization,
 * and the Disclosures and the Key Binding JWT are the "disclosures" and "kb_jwt" parameters of the unprotected header
 * of its first signature; the other signatures cannot carry them.
 *
 * It is what the Issuer returns, what the Holder stores, selects Disclosures from and presents, and what the Verifier
 * parses. The object verifies nothing: the claims it reads from the Issuer-signed JWT, for the hash algorithm and for
 * the selection, are not authenticated until the token is verified by an SDJWTVerifierInterface.
 *
 * The parts are kept as they were given, so that the string representation of a parsed SD-JWT in the compact format
 * is the parsed string: the "sd_hash" claim of a Key Binding JWT is computed over those exact bytes. In the JWS JSON
 * serialization, the JSON objects are encoded again, while the payload, the protected headers and the signatures keep
 * the strings they were given: the "sd_hash" claim is computed over the compact format of the SD-JWT made of the first
 * signature (section 8.1).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-4
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-8
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
     * A part of a JWS in the JSON serialization that is not empty, as each part of the compact format: the payload, a
     * protected header or a signature.
     */
    private const JWS_PART = '/^[A-Za-z0-9_-]+$/';

    /**
     * The parameters of the unprotected header that carry the Disclosures and the Key Binding JWT in the JWS JSON
     * serialization (section 8.1).
     */
    private const HEADER_PARAMETERS = ['disclosures', 'kb_jwt'];

    /**
     * The white space a JSON text may start with.
     */
    private const JSON_WHITE_SPACE = " \t\n\r";

    /**
     * @param string $issuerSignedJwt the Issuer-signed JWT in compact serialization; in the JWS JSON serialization, its
     *                                first signature in compact serialization
     * @param list<Disclosure> $disclosures
     * @param string $serialization the name of the JWS serializer of the Issuer-signed JWT
     * @param list<array{protected: string, header: array<mixed>, signature: string}> $signatures the signatures of
     *                                                                                          the Issuer-signed JWT
     *                                                                                          in the JWS JSON
     *                                                                                          serialization, without
     *                                                                                          the parameters of the
     *                                                                                          SD-JWT
     */
    private function __construct(
        private string $issuerSignedJwt,
        private array $disclosures,
        private ?string $keyBindingJwt,
        private string $serialization = CompactSerializer::NAME,
        private array $signatures = []
    ) {
    }

    /**
     * @param string $issuerSignedJwt the Issuer-signed JWT, in compact serialization or in a JWS JSON serialization
     *                                without the "disclosures" and "kb_jwt" header parameters
     * @param list<Disclosure> $disclosures
     *
     * @throws InvalidSerializationException if the Issuer-signed JWT is not a JWS in compact or JSON serialization, or
     *                                       if the Key Binding JWT is not a JWS in compact serialization
     */
    public static function create(string $issuerSignedJwt, array $disclosures = [], ?string $keyBindingJwt = null): self
    {
        if (self::isJson($issuerSignedJwt)) {
            [$sdJwt, $parameters] = self::readJson($issuerSignedJwt);
            if ($parameters !== []) {
                throw new InvalidSerializationException(sprintf(
                    'The Issuer-signed JWT cannot have a "%s" header parameter.',
                    array_key_first($parameters)
                ));
            }
        } else {
            self::checkIssuerSignedJwt($issuerSignedJwt);
            $sdJwt = new self($issuerSignedJwt, [], null);
        }
        if ($keyBindingJwt !== null) {
            self::checkKeyBindingJwt($keyBindingJwt);
        }

        return $sdJwt->with($disclosures, $keyBindingJwt);
    }

    /**
     * Parses an SD-JWT or an SD-JWT+KB, in the compact format or, when the string is a JSON object, in the JWS JSON
     * serialization. In the compact format, the parts are checked one after the other while the string is read, so
     * that a malformed input is rejected as soon as the malformed part is met.
     *
     * @throws InvalidSerializationException if the string is not an SD-JWT
     */
    public static function fromString(string $sdJwt): self
    {
        if (self::isJson($sdJwt)) {
            return self::fromJson($sdJwt);
        }
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

    /**
     * The Issuer-signed JWT, in the serialization of the SD-JWT. In the JWS JSON serialization, it has neither the
     * "disclosures" nor the "kb_jwt" header parameter.
     */
    public function getIssuerSignedJwt(): string
    {
        return $this->serialization === CompactSerializer::NAME ? $this->issuerSignedJwt : $this->json([]);
    }

    /**
     * The serialization of the SD-JWT, by the name of the JWS serializer of its Issuer-signed JWT: "jws_compact" for
     * the compact format, "jws_json_flattened" or "jws_json_general" for the JWS JSON serialization.
     */
    public function getSerialization(): string
    {
        return $this->serialization;
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

        return $this->with($this->disclosures, $keyBindingJwt);
    }

    public function withoutKeyBinding(): self
    {
        return $this->with($this->disclosures, null);
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
     * function of the SD-JWT. In the JWS JSON serialization, the Issuer-signed JWT is its first signature in compact
     * serialization (section 8.1).
     */
    public function getSdHash(): string
    {
        return Base64UrlSafe::encodeUnpadded(NamedInformationHash::hash($this->getHashAlgorithm(), $this->compact()));
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

        return $this->with($selected, null);
    }

    public function toString(): string
    {
        if ($this->serialization === CompactSerializer::NAME) {
            return $this->compact() . $this->keyBindingJwt;
        }
        $parameters = [
            'disclosures' => array_map(
                static fn (Disclosure $disclosure): string => $disclosure->toString(),
                $this->disclosures
            ),
        ];
        if ($this->keyBindingJwt !== null) {
            $parameters['kb_jwt'] = $this->keyBindingJwt;
        }

        return $this->json($parameters);
    }

    #[Override]
    public function __toString(): string
    {
        return $this->toString();
    }

    private static function isJson(string $value): bool
    {
        return str_starts_with(ltrim($value, self::JSON_WHITE_SPACE), '{');
    }

    /**
     * Parses an SD-JWT in the JWS JSON serialization: the Disclosures and the Key Binding JWT are read from the
     * unprotected header of the first signature.
     */
    private static function fromJson(string $json): self
    {
        [$sdJwt, $parameters] = self::readJson($json);
        $encoded = array_key_exists('disclosures', $parameters) ? $parameters['disclosures'] : [];
        if (! is_array($encoded) || ! array_is_list($encoded)) {
            throw new InvalidSerializationException('The "disclosures" header parameter must be an array of strings.');
        }
        $disclosures = [];
        foreach ($encoded as $disclosure) {
            if (! is_string($disclosure)) {
                throw new InvalidSerializationException(
                    'The "disclosures" header parameter must be an array of strings.'
                );
            }
            $disclosures[] = Disclosure::fromString($disclosure);
        }
        if (! array_key_exists('kb_jwt', $parameters)) {
            return $sdJwt->with($disclosures, null);
        }
        $keyBindingJwt = $parameters['kb_jwt'];
        if (! is_string($keyBindingJwt)) {
            throw new InvalidSerializationException('The Key Binding JWT must be a JWS in compact serialization.');
        }
        self::checkKeyBindingJwt($keyBindingJwt);

        return $sdJwt->with($disclosures, $keyBindingJwt);
    }

    /**
     * Reads an Issuer-signed JWT in the flattened or the general JWS JSON serialization. The parameters of the SD-JWT
     * are removed from the unprotected header of the first signature and returned apart; the headers of the other
     * signatures cannot have them.
     *
     * @return array{self, array<string, mixed>} the SD-JWT, without Disclosure, and the parameters of the SD-JWT
     */
    private static function readJson(string $json): array
    {
        try {
            $token = JsonConverter::decode($json);
        } catch (Throwable $throwable) {
            throw new InvalidSerializationException(
                'The JWS JSON serialization must be a JSON object.',
                0,
                $throwable
            );
        }
        $token = self::jsonObject($token, 'The JWS JSON serialization must be a JSON object.');
        $general = array_key_exists('signatures', $token);
        if ($general === array_key_exists('signature', $token)) {
            throw new InvalidSerializationException(
                'The JWS JSON serialization must have either a "signatures" member or a "signature" member.'
            );
        }
        $payload = self::jwsPart($token, 'payload');
        $entries = $general ? $token['signatures'] : [$token];
        if (! is_array($entries) || $entries === [] || ! array_is_list($entries)) {
            throw new InvalidSerializationException('The "signatures" member must be a non-empty list of JSON objects.');
        }
        $signatures = [];
        $parameters = [];
        foreach ($entries as $index => $entry) {
            $entry = self::jsonObject($entry, 'The "signatures" member must be a non-empty list of JSON objects.');
            $header = self::jsonObject(
                array_key_exists('header', $entry) ? $entry['header'] : [],
                'The "header" member must be a JSON object.'
            );
            foreach (self::HEADER_PARAMETERS as $name) {
                if (! array_key_exists($name, $header)) {
                    continue;
                }
                if ($index !== 0) {
                    throw new InvalidSerializationException(sprintf(
                        'The "%s" header parameter is only allowed in the header of the first signature.',
                        $name
                    ));
                }
                $parameters[$name] = $header[$name];
                unset($header[$name]);
            }
            $signatures[] = [
                'protected' => self::jwsPart($entry, 'protected'),
                'header' => $header,
                'signature' => self::jwsPart($entry, 'signature'),
            ];
        }
        $compact = $signatures[0]['protected'] . '.' . $payload . '.' . $signatures[0]['signature'];
        $serialization = $general ? JSONGeneralSerializer::NAME : JSONFlattenedSerializer::NAME;

        return [new self($compact, [], null, $serialization, $signatures), $parameters];
    }

    /**
     * @return array<mixed>
     */
    private static function jsonObject(mixed $value, string $message): array
    {
        if (! is_array($value) || ($value !== [] && array_is_list($value))) {
            throw new InvalidSerializationException($message);
        }

        return $value;
    }

    /**
     * @param array<mixed> $object
     */
    private static function jwsPart(array $object, string $member): string
    {
        $value = $object[$member] ?? null;
        if (! is_string($value) || preg_match(self::JWS_PART, $value) !== 1) {
            throw new InvalidSerializationException(sprintf(
                'The "%s" member must be a non-empty base64url string.',
                $member
            ));
        }

        return $value;
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
     * @param list<Disclosure> $disclosures
     */
    private function with(array $disclosures, ?string $keyBindingJwt): self
    {
        return new self($this->issuerSignedJwt, $disclosures, $keyBindingJwt, $this->serialization, $this->signatures);
    }

    /**
     * The SD-JWT without its Key Binding JWT in the compact format, the Issuer-signed JWT being its first signature in
     * the JWS JSON serialization (section 8.1).
     */
    private function compact(): string
    {
        $sdJwt = $this->issuerSignedJwt . '~';
        foreach ($this->disclosures as $disclosure) {
            $sdJwt .= $disclosure->toString() . '~';
        }

        return $sdJwt;
    }

    /**
     * Encodes the Issuer-signed JWT in its JWS JSON serialization, the given parameters of the SD-JWT added to the
     * unprotected header of its first signature. An empty unprotected header is left out.
     *
     * @param array<string, mixed> $parameters
     */
    private function json(array $parameters): string
    {
        $signatures = [];
        foreach ($this->signatures as $index => $signature) {
            $header = $index === 0 ? $signature['header'] + $parameters : $signature['header'];
            $entry = [
                'protected' => $signature['protected'],
            ];
            if ($header !== []) {
                $entry['header'] = $header;
            }
            $entry['signature'] = $signature['signature'];
            $signatures[] = $entry;
        }
        $token = [
            'payload' => explode('.', $this->issuerSignedJwt)[1],
        ];

        return JsonConverter::encode(
            $this->serialization === JSONGeneralSerializer::NAME ? $token + [
                'signatures' => $signatures,
            ] : $token + $signatures[0]
        );
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

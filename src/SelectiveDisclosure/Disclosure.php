<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\NamedInformationHash;
use JsonException;
use JsonSerializable;
use Override;
use Stringable;
use Throwable;
use function array_is_list;
use function count;
use function get_object_vars;
use function implode;
use function in_array;
use function is_array;
use function is_object;
use function is_string;
use function ltrim;
use function preg_match;
use function random_bytes;
use function sprintf;
use function str_starts_with;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * A Disclosure, as defined by RFC 9901 section 4.2: the base64url encoding of the JSON array
 * [salt, claim name, claim value] that discloses an object property, or [salt, value] that discloses an array element.
 *
 * The digest that references a Disclosure is computed over its encoded form (section 4.2.3). The encoded string is
 * therefore kept as it was received: two encodings of the same array are two different Disclosures.
 *
 * The Disclosures created by this class are serialized as the examples of the RFC are: elements separated by ", ",
 * names separated from their value by ": ", slashes left as they are and non-ASCII characters escaped. Any JSON is
 * valid (section 4.2.1) and no canonicalization is needed; this serialization is the one that reproduces the examples
 * of the RFC from their salts.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-4.2
 */
final readonly class Disclosure implements Stringable
{
    /**
     * The size, in bytes, of the generated salts: 128 bits, the minimum RFC 9901 section 9.3 recommends.
     */
    private const SALT_SIZE = 16;

    /**
     * The claim names that convey digests and cannot be disclosed (section 4.2.1).
     */
    private const RESERVED_CLAIM_NAMES = ['_sd', '...'];

    private function __construct(
        private string $disclosure,
        private string $salt,
        private ?string $claimName,
        private mixed $value
    ) {
    }

    /**
     * Creates the Disclosure of an object property. The salt is generated when it is not given.
     *
     * @throws InvalidArgumentException if the claim name is reserved or the value cannot be serialized as JSON
     */
    public static function forObjectProperty(string $claimName, mixed $value, ?string $salt = null): self
    {
        if (self::isReserved($claimName)) {
            throw new InvalidArgumentException(sprintf(
                'The claim name "%s" cannot be selectively disclosed.',
                $claimName
            ));
        }
        $salt ??= self::generateSalt();
        $disclosure = Base64UrlSafe::encodeUnpadded(self::toJson([$salt, $claimName, $value]));

        return new self($disclosure, $salt, $claimName, $value);
    }

    /**
     * Creates the Disclosure of an array element. The salt is generated when it is not given.
     *
     * @throws InvalidArgumentException if the value cannot be serialized as JSON
     */
    public static function forArrayElement(mixed $value, ?string $salt = null): self
    {
        $salt ??= self::generateSalt();
        $disclosure = Base64UrlSafe::encodeUnpadded(self::toJson([$salt, $value]));

        return new self($disclosure, $salt, null, $value);
    }

    /**
     * Parses a Disclosure.
     *
     * The decoded value must be a JSON array of three elements, whose first two are strings and whose claim name is not
     * reserved, or of two elements, whose first one is a string. Whether the Disclosure is referenced from an object
     * or from an array, and so whether it has the expected number of elements, is checked when the SD-JWT is
     * processed.
     *
     * @throws InvalidSerializationException if the value is not a Disclosure
     */
    public static function fromString(string $disclosure): self
    {
        if (preg_match('/^[A-Za-z0-9_-]+$/', $disclosure) !== 1) {
            throw new InvalidSerializationException('The Disclosure is not base64url encoded.');
        }
        try {
            $json = Base64UrlSafe::decodeNoPadding($disclosure);
        } catch (Throwable $throwable) {
            throw new InvalidSerializationException('The Disclosure is not base64url encoded.', 0, $throwable);
        }
        try {
            $array = JsonConverter::decode($json);
        } catch (Throwable $throwable) {
            throw new InvalidSerializationException('The Disclosure is not valid JSON.', 0, $throwable);
        }
        if (! is_array($array) || ! str_starts_with(ltrim($json, " \t\n\r"), '[')
            || ! in_array(count($array), [2, 3], true)) {
            throw new InvalidSerializationException('The Disclosure must be a JSON array of two or three elements.');
        }
        if (! is_string($array[0])) {
            throw new InvalidSerializationException('The salt of the Disclosure must be a string.');
        }
        if (count($array) === 2) {
            return new self($disclosure, $array[0], null, $array[1]);
        }
        if (! is_string($array[1])) {
            throw new InvalidSerializationException('The claim name of the Disclosure must be a string.');
        }
        if (self::isReserved($array[1])) {
            throw new InvalidSerializationException(sprintf(
                'The claim name "%s" cannot be selectively disclosed.',
                $array[1]
            ));
        }

        return new self($disclosure, $array[0], $array[1], $array[2]);
    }

    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * The name of the disclosed claim, or null when the Disclosure discloses an array element.
     */
    public function getClaimName(): ?string
    {
        return $this->claimName;
    }

    /**
     * The disclosed value, as it is decoded from the Disclosure: it may contain digests of other Disclosures.
     */
    public function getValue(): mixed
    {
        return $this->value;
    }

    public function isArrayElement(): bool
    {
        return $this->claimName === null;
    }

    /**
     * The base64url-encoded digest of the Disclosure, as it is embedded in the SD-JWT (section 4.2.3).
     *
     * @param string $hashAlgorithm the IANA name of the hash function, "sha-256" by default
     */
    public function digest(string $hashAlgorithm = SDJWT::DEFAULT_HASH_ALGORITHM): string
    {
        return Base64UrlSafe::encodeUnpadded(NamedInformationHash::hash($hashAlgorithm, $this->disclosure));
    }

    public function toString(): string
    {
        return $this->disclosure;
    }

    #[Override]
    public function __toString(): string
    {
        return $this->disclosure;
    }

    private static function isReserved(string $claimName): bool
    {
        return in_array($claimName, self::RESERVED_CLAIM_NAMES, true);
    }

    private static function generateSalt(): string
    {
        return Base64UrlSafe::encodeUnpadded(random_bytes(self::SALT_SIZE));
    }

    /**
     * Serializes a value as the examples of the RFC are. A list is a JSON array, any other PHP array, a stdClass or an
     * object a JSON object; a JsonSerializable is serialized as the value it gives.
     */
    private static function toJson(mixed $value): string
    {
        if ($value instanceof JsonSerializable) {
            return self::toJson($value->jsonSerialize());
        }
        if (is_object($value)) {
            return self::toJsonObject(get_object_vars($value));
        }
        if (is_array($value)) {
            return array_is_list($value) ? self::toJsonArray($value) : self::toJsonObject($value);
        }
        try {
            return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('The value cannot be serialized as JSON.', 0, $exception);
        }
    }

    /**
     * @param list<mixed> $elements
     */
    private static function toJsonArray(array $elements): string
    {
        $encoded = [];
        foreach ($elements as $element) {
            $encoded[] = self::toJson($element);
        }

        return '[' . implode(', ', $encoded) . ']';
    }

    /**
     * @param array<mixed> $members
     */
    private static function toJsonObject(array $members): string
    {
        $encoded = [];
        foreach ($members as $name => $member) {
            $encoded[] = self::toJson((string) $name) . ': ' . self::toJson($member);
        }

        return '{' . implode(', ', $encoded) . '}';
    }
}

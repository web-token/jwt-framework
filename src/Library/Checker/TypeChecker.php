<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Override;
use function count;
use function in_array;
use function is_string;

/**
 * Checks the "typ" header parameter against an explicit list of accepted media types.
 *
 * RFC 8725 section 3.11 recommends explicit typing: the "typ" header names the profile of the token
 * (e.g. "at+jwt", "dpop+jwt", "secevent+jwt") and the verifier rejects any other value, which prevents a token
 * issued for one purpose from being replayed for another one. This checker only accepts values from the protected
 * header, as the guarantee relies on the value being integrity protected.
 *
 * Values are compared as defined in RFC 7515 section 4.1.9: media types are case-insensitive and the "application/"
 * prefix may be omitted, so "JWT", "jwt" and "application/jwt" designate the same type.
 */
final readonly class TypeChecker implements HeaderChecker
{
    private const HEADER_NAME = 'typ';

    private const DEFAULT_TOP_LEVEL_TYPE = 'application/';

    /**
     * @var non-empty-list<non-empty-string>
     */
    private array $acceptedTypes;

    /**
     * @param string|string[] $acceptedTypes the accepted media types, with or without the "application/" prefix
     */
    public function __construct(string|array $acceptedTypes)
    {
        $normalizedTypes = [];
        foreach ((array) $acceptedTypes as $acceptedType) {
            if (! is_string($acceptedType) || $acceptedType === '') {
                throw new InvalidArgumentException('The accepted types must be non-empty strings.');
            }
            $normalizedTypes[] = self::normalize($acceptedType);
        }
        if (count($normalizedTypes) === 0) {
            throw new InvalidArgumentException('At least one accepted type must be provided.');
        }
        $this->acceptedTypes = array_values(array_unique($normalizedTypes));
    }

    #[Override]
    public function checkHeader(mixed $value): void
    {
        if (! is_string($value)) {
            throw new InvalidHeaderException('"typ" must be a string.', self::HEADER_NAME, $value);
        }
        if (! in_array(self::normalize($value), $this->acceptedTypes, true)) {
            throw new InvalidHeaderException('Unsupported type.', self::HEADER_NAME, $value);
        }
    }

    #[Override]
    public function supportedHeader(): string
    {
        return self::HEADER_NAME;
    }

    #[Override]
    public function protectedHeaderOnly(): bool
    {
        return true;
    }

    /**
     * Lowercases the media type and prepends "application/" when no other top-level type is given, as required
     * by RFC 7515 section 4.1.9.
     *
     * @return non-empty-string
     */
    private static function normalize(string $type): string
    {
        $type = strtolower($type);
        if (! str_contains($type, '/')) {
            $type = self::DEFAULT_TOP_LEVEL_TYPE . $type;
        }

        return $type;
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Util\InheritanceChecker;
use function array_key_exists;
use function sprintf;
use function trigger_deprecation;

/**
 * One signature of a JWS, with the two headers it was computed with.
 *
 * The protected header of a signature is defined by its encoded form: that string is what the signature covers, and
 * it is the only proof that the parameters it carries were protected. A signature built without an encoded protected
 * header therefore has no protected header at all, and the decoded one given to the constructor is discarded rather
 * than exposed, so that getProtectedHeader() never advertises parameters no signature protects. The class will be
 * final and readonly in 5.0.0, where the two arguments must agree.
 *
 * @final The class will be final and readonly in 5.0.0: build it with its constructor instead of extending it.
 */
class Signature
{
    private readonly ?string $encodedProtectedHeader;

    /**
     * @var array<string, mixed>
     */
    private readonly array $protectedHeader;

    /**
     * @param array<string, mixed> $protectedHeader        The decoded protected header; it is discarded, and passing a
     *                                                     non-empty one is deprecated since 4.3.0, when
     *                                                     $encodedProtectedHeader is null
     * @param string|null          $encodedProtectedHeader The Base64Url encoded protected header the signature covers,
     *                                                     or null when the signature has no protected header
     * @param array<string, mixed> $header                 The unprotected header
     */
    public function __construct(
        private readonly string $signature,
        array $protectedHeader,
        ?string $encodedProtectedHeader,
        private readonly array $header
    ) {
        InheritanceChecker::warnIfValueObjectExtended(static::class, self::class);
        if ($encodedProtectedHeader === null && $protectedHeader !== []) {
            trigger_deprecation(
                'web-token/jwt-framework',
                '4.3.0',
                'Passing a protected header to "%s" without its encoded form is deprecated and will throw an "%s" in 5.0.0. The header is discarded: a signature that does not cover an encoded protected header has no protected header.',
                self::class,
                InvalidArgumentException::class
            );
        }
        $this->protectedHeader = $encodedProtectedHeader === null ? [] : $protectedHeader;
        $this->encodedProtectedHeader = $encodedProtectedHeader;
    }

    /**
     * The protected header associated with the signature.
     *
     * @return array<string, mixed>
     */
    public function getProtectedHeader(): array
    {
        return $this->protectedHeader;
    }

    /**
     * The unprotected header associated with the signature.
     *
     * @return array<string, mixed>
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * The protected header associated with the signature.
     */
    public function getEncodedProtectedHeader(): ?string
    {
        return $this->encodedProtectedHeader;
    }

    /**
     * Returns the value of the protected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getProtectedHeaderParameter(string $key)
    {
        if ($this->hasProtectedHeaderParameter($key)) {
            return $this->getProtectedHeader()[$key];
        }

        throw new InvalidHeaderParameterException(sprintf('The protected header "%s" does not exist', $key));
    }

    /**
     * Returns true if the protected header has the given parameter.
     *
     * @param string $key The key
     */
    public function hasProtectedHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->getProtectedHeader());
    }

    /**
     * Returns the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getHeaderParameter(string $key)
    {
        if (array_key_exists($key, $this->header)) {
            return $this->header[$key];
        }

        throw new InvalidHeaderParameterException(sprintf('The header "%s" does not exist', $key));
    }

    /**
     * Returns true if the unprotected header has the given parameter.
     *
     * @param string $key The key
     */
    public function hasHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->header);
    }

    /**
     * Returns the value of the signature.
     */
    public function getSignature(): string
    {
        return $this->signature;
    }
}

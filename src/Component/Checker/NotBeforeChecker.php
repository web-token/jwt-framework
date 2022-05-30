<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use function is_float;
use function is_int;

/**
 * This class is a claim checker. When the "nbf" is present, it will compare the value with the current timestamp.
 */
final class NotBeforeChecker implements ClaimChecker, HeaderChecker
{
    private const NAME = 'nbf';

    public function __construct(
        private readonly int $allowedTimeDrift = 0,
        private readonly bool $protectedHeaderOnly = false
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim(mixed $value): void
    {
        if (! is_float($value) && ! is_int($value)) {
            throw new InvalidClaimException('"nbf" must be an integer.', self::NAME, $value);
        }
        if (time() < $value - $this->allowedTimeDrift) {
            throw new InvalidClaimException('The JWT can not be used yet.', self::NAME, $value);
        }
    }

    public function supportedClaim(): string
    {
        return self::NAME;
    }

    public function checkHeader(mixed $value): void
    {
        if (! is_float($value) && ! is_int($value)) {
            throw new InvalidHeaderException('"nbf" must be an integer.', self::NAME, $value);
        }
        if (time() < $value - $this->allowedTimeDrift) {
            throw new InvalidHeaderException('The JWT can not be used yet.', self::NAME, $value);
        }
    }

    public function supportedHeader(): string
    {
        return self::NAME;
    }

    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeaderOnly;
    }
}

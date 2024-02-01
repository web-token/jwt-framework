<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

/**
 * @see \Jose\Tests\Component\Checker\IsEqualCheckerTest
 */
final class IsEqualChecker implements ClaimChecker, HeaderChecker
{
    /**
     * @param string $key                 The claim or header parameter name to check.
     * @param mixed  $value               The expected value.
     * @param bool   $protectedHeaderOnly [optional] Whether the header parameter MUST be protected.
     *                                    This option has no effect for claim checkers.
     */
    public function __construct(
        private readonly string $key,
        private readonly mixed $value,
        private readonly bool $protectedHeaderOnly = true
    ) {
    }

    public function checkClaim(mixed $value): void
    {
        if ($value !== $this->value) {
            throw new InvalidClaimException(sprintf('The "%s" claim is invalid.', $this->key), $this->key, $value);
        }
    }

    public function supportedClaim(): string
    {
        return $this->key;
    }

    public function checkHeader(mixed $value): void
    {
        if ($value !== $this->value) {
            throw new InvalidHeaderException(sprintf('The "%s" header is invalid.', $this->key), $this->key, $value);
        }
    }

    public function supportedHeader(): string
    {
        return $this->key;
    }

    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeaderOnly;
    }
}

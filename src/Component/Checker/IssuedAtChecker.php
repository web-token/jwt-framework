<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use function is_float;
use function is_int;
use Psr\Clock\ClockInterface;

/**
 * This class is a claim checker. When the "iat" is present, it will compare the value with the current timestamp.
 */
final class IssuedAtChecker implements ClaimChecker, HeaderChecker
{
    private const NAME = 'iat';

    public function __construct(
        private readonly int $allowedTimeDrift = 0,
        private readonly bool $protectedHeaderOnly = false,
        private readonly ClockInterface $clock = new InternalClock(),
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim(mixed $value): void
    {
        if (! is_float($value) && ! is_int($value)) {
            throw new InvalidClaimException('"iat" must be an integer.', self::NAME, $value);
        }

        $now = $this->clock->now()
            ->getTimestamp();
        if ($now < $value - $this->allowedTimeDrift) {
            throw new InvalidClaimException('The JWT is issued in the future.', self::NAME, $value);
        }
    }

    public function supportedClaim(): string
    {
        return self::NAME;
    }

    public function checkHeader(mixed $value): void
    {
        if (! is_float($value) && ! is_int($value)) {
            throw new InvalidHeaderException('The header "iat" must be an integer.', self::NAME, $value);
        }

        $now = $this->clock->now()
            ->getTimestamp();
        if ($now < $value - $this->allowedTimeDrift) {
            throw new InvalidHeaderException('The JWT is issued in the future.', self::NAME, $value);
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

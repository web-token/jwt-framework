<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use Psr\Clock\ClockInterface;
use function is_float;
use function is_int;

/**
 * This class is a claim checker. When the "iat" is present, it will compare the value with the current timestamp.
 */
final class IssuedAtChecker implements ClaimChecker, HeaderChecker
{
    private const NAME = 'iat';

    private readonly ClockInterface $clock;

    public function __construct(
        private readonly int $allowedTimeDrift = 0,
        private readonly bool $protectedHeaderOnly = false,
        ?ClockInterface $clock = null,
    ) {
        if ($clock === null) {
            trigger_deprecation(
                'web-token/jwt-library',
                '3.3.0',
                'The parameter "$clock" will become mandatory in 4.0.0. Please set a valid PSR Clock implementation instead of "null".'
            );
            $clock = new InternalClock();
        }
        $this->clock = $clock;
    }

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

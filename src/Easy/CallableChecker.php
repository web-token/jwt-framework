<?php

declare(strict_types=1);

namespace Jose\Easy;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;

final class CallableChecker implements ClaimChecker, HeaderChecker
{
    /**
     * @var callable
     */
    private $callable;

    public function __construct(
        private string $key,
        callable $callable
    ) {
        $this->callable = $callable;
    }

    public function checkClaim($value): void
    {
        $callable = $this->callable;
        $isValid = $callable($value);
        if (! $isValid) {
            throw new InvalidClaimException(sprintf('Invalid claim "%s"', $this->key), $this->key, $value);
        }
    }

    public function supportedClaim(): string
    {
        return $this->key;
    }

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value): void
    {
        $callable = $this->callable;
        $isValid = $callable($value);
        if (! $isValid) {
            throw new InvalidHeaderException(sprintf('Invalid header "%s"', $this->key), $this->key, $value);
        }
    }

    public function supportedHeader(): string
    {
        return $this->key;
    }

    public function protectedHeaderOnly(): bool
    {
        return true;
    }
}

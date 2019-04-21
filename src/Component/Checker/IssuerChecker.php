<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker;

/**
 * This class is a header parameter and claim checker.
 * When the "iss" header parameter or claim is present, it will check if the value is within the allowed ones.
 */
final class IssuerChecker implements ClaimChecker, HeaderChecker
{
    private const CLAIM_NAME = 'iss';

    /**
     * @var bool
     */
    private $protectedHeader = false;

    /**
     * @var array
     */
    private $issuers;

    public function __construct(array $issuer, bool $protectedHeader = false)
    {
        $this->issuers = $issuer;
        $this->protectedHeader = $protectedHeader;
    }

    public function checkClaim($value): void
    {
        $this->checkValue($value, InvalidClaimException::class);
    }

    public function checkHeader($value): void
    {
        $this->checkValue($value, InvalidHeaderException::class);
    }

    public function supportedClaim(): string
    {
        return self::CLAIM_NAME;
    }

    public function supportedHeader(): string
    {
        return self::CLAIM_NAME;
    }

    public function protectedHeaderOnly(): bool
    {
        return $this->protectedHeader;
    }

    /**
     * @param mixed $value
     */
    private function checkValue($value, string $class): void
    {
        if (!\is_string($value)) {
            throw new $class('Invalid value.', self::CLAIM_NAME, $value);
        }
        if (!\in_array($value, $this->issuers, true)) {
            throw new $class('Unknown issuer.', self::CLAIM_NAME, $value);
        }
    }
}

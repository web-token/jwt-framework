<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests\Stub;

use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\InvalidHeaderException;

class IssuerChecker implements HeaderChecker
{
    private const CLAIM_NAME = 'iss';

    /**
     * @var string
     */
    private $issuer;

    /**
     * IssuerChecker constructor.
     */
    public function __construct(string $issuer)
    {
        $this->issuer = $issuer;
    }

    public function checkHeader($value)
    {
        if (!\is_string($value) || $value !== $this->issuer) {
            throw new InvalidHeaderException('Bad issuer.', 'iss', $value);
        }
    }

    public function supportedHeader(): string
    {
        return self::CLAIM_NAME;
    }

    public function protectedHeaderOnly(): bool
    {
        return false;
    }
}

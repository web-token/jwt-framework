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

namespace Jose\Component\Checker;

class MissingMandatoryClaimException extends \Exception
{
    /**
     * @var string[]
     */
    private $claims;

    /**
     * MissingMandatoryClaimException constructor.
     *
     * @param string[] $claims
     */
    public function __construct(string $message, array $claims)
    {
        parent::__construct($message);

        $this->claims = $claims;
    }

    /**
     * @return string[]
     */
    public function getClaims(): array
    {
        return $this->claims;
    }
}

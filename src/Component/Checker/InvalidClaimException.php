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

/**
 * This exception is thrown by claim checkers when a claim check failed.
 */
class InvalidClaimException extends \Exception
{
    /**
     * @var string
     */
    private $claim;

    /**
     * @var mixed
     */
    private $value;

    /**
     * InvalidClaimException constructor.
     */
    public function __construct(string $message, string $claim, $value)
    {
        parent::__construct($message);

        $this->claim = $claim;
        $this->value = $value;
    }

    /**
     * Returns the claim that caused the exception.
     */
    public function getClaim(): string
    {
        return $this->claim;
    }

    /**
     * Returns the claim value that caused the exception.
     */
    public function getValue()
    {
        return $this->value;
    }
}

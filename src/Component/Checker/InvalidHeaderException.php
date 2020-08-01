<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker;

use Exception;

/**
 * This exception is thrown by header parameter checkers when a header parameter check failed.
 */
class InvalidHeaderException extends Exception
{
    /**
     * @var string
     */
    private $header;

    /**
     * @var mixed
     */
    private $value;

    /**
     * @param mixed $value
     */
    public function __construct(string $message, string $header, $value)
    {
        parent::__construct($message);

        $this->header = $header;
        $this->value = $value;
    }

    /**
     * Returns the header parameter that caused the exception.
     */
    public function getHeader(): string
    {
        return $this->header;
    }

    /**
     * Returns the header parameter value that caused the exception.
     *
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }
}

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker;

/**
 * Class InvalidHeaderException.
 */
final class InvalidHeaderException extends \Error
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
     * InvalidHeaderException constructor.
     * @param string $message
     * @param string $header
     * @param mixed  $value
     */
    public function __construct(string $message, string $header, $value)
    {
        parent::__construct($message);

        $this->header = $header;
        $this->value = $value;
    }

    /**
     * @return string
     */
    public function getHeader(): string
    {
        return $this->header;
    }

    /**
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }
}

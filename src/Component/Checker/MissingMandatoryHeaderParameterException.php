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

class MissingMandatoryHeaderParameterException extends Exception
{
    /**
     * @var string[]
     */
    private $parameters;

    /**
     * MissingMandatoryHeaderParameterException constructor.
     *
     * @param string[] $parameters
     */
    public function __construct(string $message, array $parameters)
    {
        parent::__construct($message);

        $this->parameters = $parameters;
    }

    /**
     * @return string[]
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }
}

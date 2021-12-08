<?php

declare(strict_types=1);

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

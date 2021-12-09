<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use Exception;

class MissingMandatoryClaimException extends Exception implements ClaimExceptionInterface
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

<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

interface ClaimChecker
{
    /**
     * When the token has the applicable claim, the value is checked. If for some reason the value is not valid, an
     * InvalidClaimException must be thrown.
     */
    public function checkClaim(mixed $value): void;

    /**
     * The method returns the claim to be checked.
     */
    public function supportedClaim(): string;
}

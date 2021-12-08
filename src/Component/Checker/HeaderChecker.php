<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

interface HeaderChecker
{
    /**
     * This method is called when the header parameter is present. If for some reason the value is not valid, an
     * InvalidHeaderException must be thrown.
     */
    public function checkHeader(mixed $value): void;

    /**
     * The method returns the header parameter to be checked.
     */
    public function supportedHeader(): string;

    /**
     * When true, the header parameter to be checked MUST be set in the protected header of the token.
     */
    public function protectedHeaderOnly(): bool;
}

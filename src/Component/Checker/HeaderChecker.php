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

interface HeaderChecker
{
    /**
     * This method is called when the header parameter is present.
     * If for some reason the value is not valid, an InvalidHeaderException must be thrown.
     *
     *
     * @throws InvalidHeaderException
     */
    public function checkHeader($value);

    /**
     * The method returns the header parameter to be checked.
     */
    public function supportedHeader(): string;

    /**
     * When true, the header parameter to be checked MUST be set in the protected header of the token.
     */
    public function protectedHeaderOnly(): bool;
}

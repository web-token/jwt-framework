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
 * Interface HeaderChecker.
 */
interface HeaderChecker
{
    /**
     * @param $value
     *
     * @throws \InvalidArgumentException
     */
    public function checkHeader($value);

    /**
     * @return string
     */
    public function supportedHeader(): string;

    /**
     * @return bool
     */
    public function protectedHeaderOnly(): bool;
}

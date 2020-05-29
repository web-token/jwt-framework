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

use function is_bool;

/**
 * This class is a header parameter checker.
 * When the "b64" is present, it will check if the value is a boolean or not.
 *
 * The use of this checker will allow the use of token with unencoded payload.
 */
final class UnencodedPayloadChecker implements HeaderChecker
{
    private const HEADER_NAME = 'b64';

    /**
     * {@inheritdoc}
     *
     * @throws InvalidHeaderException if the header parameter "b64" is not a boolean
     */
    public function checkHeader($value): void
    {
        if (!is_bool($value)) {
            throw new InvalidHeaderException('"b64" must be a boolean.', self::HEADER_NAME, $value);
        }
    }

    public function supportedHeader(): string
    {
        return self::HEADER_NAME;
    }

    public function protectedHeaderOnly(): bool
    {
        return true;
    }
}

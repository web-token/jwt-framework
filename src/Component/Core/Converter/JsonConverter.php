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

namespace Jose\Component\Core\Converter;

/**
 * @deprecated This interface is deprecated in v1.3 and will be removed in v2.0.
 */
interface JsonConverter
{
    /**
     * Convert the payload into a string.
     */
    public function encode($payload): string;

    /**
     * Convert a string into payload.
     */
    public function decode(string $payload, bool $associativeArray = true);
}

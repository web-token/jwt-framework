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

namespace Jose\Component\Core\Converter;

/**
 * Interface JsonConverterInterface.
 */
interface JsonConverterInterface
{
    /**
     * @param $payload
     *
     * @return string
     */
    public function encode($payload): string;

    /**
     * @param string $payload
     * @param bool   $associativeArray
     *
     * @return mixed
     */
    public function decode(string $payload, bool $associativeArray = true);
}

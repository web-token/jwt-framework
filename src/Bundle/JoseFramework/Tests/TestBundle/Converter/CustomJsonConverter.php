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

namespace Jose\Bundle\JoseFramework\Tests\TestBundle\Converter;

use Jose\Component\Core\Converter\JsonConverter;

/**
 * Class CustomJsonConverter.
 */
class CustomJsonConverter implements JsonConverter
{
    /**
     * @var int
     */
    private $options;

    /**
     * CustomJsonConverter constructor.
     */
    public function __construct()
    {
        $this->options = JSON_UNESCAPED_UNICODE;
    }

    public function encode($payload): string
    {
        return \json_encode($payload, $this->options, 512);
    }

    public function decode(string $payload, bool $associativeArray = true)
    {
        return \json_decode($payload, $associativeArray, 512, $this->options);
    }
}

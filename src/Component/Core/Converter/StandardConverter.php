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
 * @deprecated This class is deprecated in v1.3 and will be removed in v2.0
 */
final class StandardConverter implements JsonConverter
{
    /**
     * @var int
     */
    private $options;

    /**
     * @var int
     */
    private $depth;

    /**
     * StandardJsonEncoder constructor.
     * See also json_encode and json_decode parameters.
     */
    public function __construct(int $options = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE, int $depth = 512)
    {
        $this->options = $options;
        $this->depth = $depth;
    }

    public function encode($payload): string
    {
        return \json_encode($payload, $this->options, $this->depth);
    }

    public function decode(string $payload, bool $associativeArray = true)
    {
        return \json_decode($payload, $associativeArray, $this->depth, $this->options);
    }
}

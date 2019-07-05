<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Easy;

final class JWT
{
    public $payload;
    public $header;

    public function __construct()
    {
        $this->payload = new ParameterBag();
        $this->header = new ParameterBag();
    }
}

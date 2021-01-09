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

namespace Jose\Tests\Component\Core;

use Jose\Component\Core\Algorithm;

class FooAlgorithm implements Algorithm
{
    public function name(): string
    {
        return 'foo';
    }

    public function allowedKeyTypes(): array
    {
        return ['FOO'];
    }
}

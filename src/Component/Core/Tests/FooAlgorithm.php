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

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\Algorithm;

class FooAlgorithm implements Algorithm
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'foo';
    }

    /**
     * {@inheritdoc}
     */
    public function allowedKeyTypes(): array
    {
        return ['FOO'];
    }
}

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

namespace Jose\Component\Core;

/**
 * Interface Algorithm.
 */
interface Algorithm
{
    /**
     * @return string Returns the name of the algorithm
     */
    public function name(): string;

    /**
     * @return array[] Returns the key types suitable for this algorithm
     */
    public function allowedKeyTypes(): array;
}

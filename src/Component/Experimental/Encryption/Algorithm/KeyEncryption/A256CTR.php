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

namespace Jose\Component\Experimental\Encryption\Algorithm\KeyEncryption;

final class A256CTR extends AESCTR
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'A256CTR';
    }

    /**
     * {@inheritdoc}
     */
    protected function getMode(): string
    {
        return 'aes-256-ctr';
    }
}

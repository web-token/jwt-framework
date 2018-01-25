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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

/**
 * Class A128GCMKW.
 */
final class A128GCMKW extends AESGCMKW
{
    /**
     * {@inheritdoc}
     */
    protected function getKeySize(): int
    {
        return 128;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'A128GCMKW';
    }
}

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

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

/**
 * Class A256GCM.
 */
final class A256GCM extends AESGCM
{
    /**
     * {@inheritdoc}
     */
    protected function getKeySize(): int
    {
        return 256;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'A256GCM';
    }
}

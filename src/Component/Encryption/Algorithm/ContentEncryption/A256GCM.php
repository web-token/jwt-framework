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

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

/**
 * Class A256GCM.
 */
final class A256GCM extends AESGCM
{
    /**
     * {@inheritdoc}
     */
    public function getCEKSize(): int
    {
        return 256;
    }

    /**
     * {@inheritdoc}
     */
    protected function getMode(): string
    {
        return 'aes-256-gcm';
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'A256GCM';
    }
}

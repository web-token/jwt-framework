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

namespace Jose\Component\Experimental\Encryption\Algorithm\ContentEncryption;

final class A256CCM_64_64 extends AESCCM
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
        return 'aes-256-ccm';
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'A256CCM-16-64';
    }

    protected function getTagLength(): int
    {
        return 8;
    }

    public function getIVSize(): int
    {
        return 7;
    }
}

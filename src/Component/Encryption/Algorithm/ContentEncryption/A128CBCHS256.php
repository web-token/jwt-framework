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
 * Class A128CBCHS256.
 */
final class A128CBCHS256 extends AESCBCHS
{
    /**
     * {@inheritdoc}
     */
    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    /**
     * {@inheritdoc}
     */
    protected function getMode(): string
    {
        return 'aes-128-cbc';
    }

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
    public function name(): string
    {
        return 'A128CBC-HS256';
    }
}

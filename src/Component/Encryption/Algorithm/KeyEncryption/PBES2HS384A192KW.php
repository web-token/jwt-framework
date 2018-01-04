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

use AESKW\A192KW as Wrapper;

/**
 * Class PBES2HS384A192KW.
 */
final class PBES2HS384A192KW extends PBES2AESKW
{
    /**
     * {@inheritdoc}
     */
    protected function getWrapper()
    {
        return new Wrapper();
    }

    /**
     * {@inheritdoc}
     */
    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    /**
     * {@inheritdoc}
     */
    protected function getKeySize(): int
    {
        return 24;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'PBES2-HS384+A192KW';
    }
}

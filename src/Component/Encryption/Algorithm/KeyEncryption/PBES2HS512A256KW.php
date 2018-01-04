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

use AESKW\A256KW as Wrapper;

/**
 * Class PBES2HS512A256KW.
 */
final class PBES2HS512A256KW extends PBES2AESKW
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
        return 'sha512';
    }

    /**
     * {@inheritdoc}
     */
    protected function getKeySize(): int
    {
        return 32;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'PBES2-HS512+A256KW';
    }
}

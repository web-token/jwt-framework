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
 * Class ECDHESA192KW.
 */
final class ECDHESA192KW extends ECDHESAESKW
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
    public function name(): string
    {
        return 'ECDH-ES+A192KW';
    }

    /**
     * {@inheritdoc}
     */
    protected function getKeyLength(): int
    {
        return 192;
    }
}

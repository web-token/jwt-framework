<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

final class ECDHESA256KW extends ECDHESAESKW
{
    public function name(): string
    {
        return 'ECDH-ES+A256KW';
    }

    protected function getWrapper()
    {
        return new Wrapper();
    }

    protected function getKeyLength(): int
    {
        return 256;
    }
}

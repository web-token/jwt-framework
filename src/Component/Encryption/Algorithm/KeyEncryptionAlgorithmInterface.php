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

namespace Jose\Component\Encryption\Algorithm;

use Jose\Component\Core\AlgorithmInterface;

/**
 * Interface KeyEncryptionAlgorithmInterface.
 */
interface KeyEncryptionAlgorithmInterface extends AlgorithmInterface
{
    public const MODE_DIRECT = 'dir';
    public const MODE_ENCRYPT = 'enc';
    public const MODE_WRAP = 'wrap';
    public const MODE_AGREEMENT = 'agree';

    /**
     * @return string
     */
    public function getKeyManagementMode(): string;
}

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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;

interface SourceWithCompilerPasses extends Source
{
    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array;
}

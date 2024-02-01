<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;

interface SourceWithCompilerPasses extends Source
{
    /**
     * @return CompilerPassInterface[]
     */
    public function getCompilerPasses(): array;
}

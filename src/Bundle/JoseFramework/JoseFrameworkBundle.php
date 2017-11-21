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

namespace Jose\Bundle\JoseFramework;

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\AlgorithmCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\CheckerCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\DataCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\JWECollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\JWSCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\KeyCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\JoseFrameworkExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Class JoseFrameworkBundle.
 */
final class JoseFrameworkBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function getContainerExtension()
    {
        return new JoseFrameworkExtension('jose');
    }

    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $container->addCompilerPass(new DataCollectorCompilerPass());
        $container->addCompilerPass(new JWSCollectorCompilerPass());
        $container->addCompilerPass(new JWECollectorCompilerPass());
        $container->addCompilerPass(new KeyCollectorCompilerPass());
        $container->addCompilerPass(new CheckerCollectorCompilerPass());
        $container->addCompilerPass(new AlgorithmCompilerPass());
    }
}

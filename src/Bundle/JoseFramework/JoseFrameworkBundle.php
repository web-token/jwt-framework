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

use Jose\Bundle\JoseFramework\DependencyInjection\Compiler;
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
        $container->addCompilerPass(new Compiler\DataCollectorCompilerPass());
        $container->addCompilerPass(new Compiler\JWSCollectorCompilerPass());
        $container->addCompilerPass(new Compiler\JWECollectorCompilerPass());
        $container->addCompilerPass(new Compiler\KeyCollectorCompilerPass());
        $container->addCompilerPass(new Compiler\CheckerCollectorCompilerPass());
        $container->addCompilerPass(new Compiler\AlgorithmCompilerPass());
        $container->addCompilerPass(new Compiler\ClaimCheckerCompilerPass());
        $container->addCompilerPass(new Compiler\HeaderCheckerCompilerPass());
        $container->addCompilerPass(new Compiler\KeyAnalyzerCompilerPass());
        $container->addCompilerPass(new Compiler\CompressionMethodCompilerPass());
        $container->addCompilerPass(new Compiler\EncryptionSerializerCompilerPass());
        $container->addCompilerPass(new Compiler\KeySetControllerCompilerPass());
        $container->addCompilerPass(new Compiler\SignatureSerializerCompilerPass());
    }
}

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

use Jose\Bundle\Checker\DependencyInjection\Compiler\ClaimCheckerCompilerPass;
use Jose\Bundle\Checker\DependencyInjection\Compiler\HeaderCheckerCompilerPass;
use Jose\Bundle\Console\DependencyInjection\Compiler\KeyAnalyzerCompilerPass;
use Jose\Bundle\Encryption\DependencyInjection\Compiler\CompressionMethodCompilerPass;
use Jose\Bundle\Encryption\DependencyInjection\Compiler\SerializerCompilerPass as EncryptionSerializerCompilerPass;
use Jose\Bundle\Signature\DependencyInjection\Compiler\SerializerCompilerPass as SignatureSerializerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\AlgorithmCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\CheckerCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\DataCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\JWECollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\JWSCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\KeyCollectorCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\JoseFrameworkExtension;
use Jose\Bundle\KeyManagement\DependencyInjection\Compiler\KeySetControllerCompilerPass;
use Symfony\Component\Config\Resource\ClassExistenceResource;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
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

        $this->addCompilerPassIfExists($container, ClaimCheckerCompilerPass::class);
        $this->addCompilerPassIfExists($container, HeaderCheckerCompilerPass::class);
        $this->addCompilerPassIfExists($container, KeyAnalyzerCompilerPass::class);
        $this->addCompilerPassIfExists($container, CompressionMethodCompilerPass::class);
        $this->addCompilerPassIfExists($container, EncryptionSerializerCompilerPass::class);
        $this->addCompilerPassIfExists($container, KeySetControllerCompilerPass::class);
        $this->addCompilerPassIfExists($container, SignatureSerializerCompilerPass::class);
    }

    private function addCompilerPassIfExists(ContainerBuilder $container, $class, $type = PassConfig::TYPE_BEFORE_OPTIMIZATION, $priority = 0)
    {
        $container->addResource(new ClassExistenceResource($class));
        if (class_exists($class)) {
            $container->addCompilerPass(new $class(), $type, $priority);
        }
    }
}

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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Bundle\JoseFramework\Normalizer\JWENormalizer;
use Jose\Bundle\JoseFramework\Normalizer\JWSNormalizer;
use Jose\Bundle\JoseFramework\Serializer\JWEEncoder;
use Jose\Bundle\JoseFramework\Serializer\JWSEncoder;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class SymfonySerializerCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!\class_exists('Symfony\Component\Serializer\Serializer')) {
            return;
        }

        if ($container->hasDefinition(JWSSerializerManagerFactory::class)) {
            $container->autowire(JWSEncoder::class, JWSEncoder::class)
                ->setPrivate(true)
                ->addTag('serializer.encoder');
            $container->autowire(JWSNormalizer::class, JWSNormalizer::class)
                ->setPrivate(true)
                ->addTag('serializer.normalizer');
        }

        if ($container->hasDefinition(JWESerializerManagerFactory::class)) {
            $container->autowire(JWEEncoder::class, JWEEncoder::class)
                ->setPrivate(true)
                ->addTag('serializer.encoder');
            $container->autowire(JWENormalizer::class, JWENormalizer::class)
                ->setPrivate(true)
                ->addTag('serializer.normalizer');
        }
    }
}

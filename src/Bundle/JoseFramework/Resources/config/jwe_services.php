<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Bundle\JoseFramework\Services\JWEDecrypterFactory;
use Jose\Bundle\JoseFramework\Services\JWELoaderFactory;
use Jose\Component\Encryption\JWETokenSupport;

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(JWEBuilderFactory::class)
        ->public();

    $container->set(JWEDecrypterFactory::class)
        ->public();

    $container->set(JWELoaderFactory::class)
        ->public();

    $container->set(JWETokenSupport::class);
};

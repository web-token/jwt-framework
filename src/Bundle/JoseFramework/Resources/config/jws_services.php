<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory;
use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory;
use Jose\Bundle\JoseFramework\Services\JWSVerifierFactory;
use Jose\Component\Signature\JWSTokenSupport;

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

    $container->set(JWSBuilderFactory::class)
        ->public();

    $container->set(JWSVerifierFactory::class)
        ->public();

    $container->set(JWSLoaderFactory::class)
        ->public();

    $container->set(JWSTokenSupport::class);
};

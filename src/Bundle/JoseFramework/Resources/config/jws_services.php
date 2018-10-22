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

use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory;
use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory;
use Jose\Component\Signature;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(JWSBuilderFactory::class)
        ->public();

    $container->set(Signature\JWSVerifierFactory::class)
        ->public();

    $container->set(JWSLoaderFactory::class)
        ->public();

    $container->set(Signature\JWSTokenSupport::class);
};

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Jose\Component\Signature;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(Signature\JWSBuilderFactory::class)
        ->public();
    $container->set(Signature\JWSVerifierFactory::class)
        ->public();
    $container->set(Signature\JWSLoaderFactory::class)
        ->public();
    $container->set(Signature\JWSTokenSupport::class);
};

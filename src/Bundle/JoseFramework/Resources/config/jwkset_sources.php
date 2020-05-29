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

use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSetSource;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->public()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(JWKSetSource\JWKSet::class);
    $container->set(JWKSetSource\JKU::class);
    $container->set(JWKSetSource\X5U::class);
};

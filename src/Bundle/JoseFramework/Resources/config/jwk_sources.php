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

use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->public()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(JWKSource\KeyFile::class);
    $container->set(JWKSource\P12::class);
    $container->set(JWKSource\CertificateFile::class);
    $container->set(JWKSource\Values::class);
    $container->set(JWKSource\Secret::class);
    $container->set(JWKSource\JWK::class);
    $container->set(JWKSource\X5C::class);
    $container->set(JWKSource\JWKSet::class);
};

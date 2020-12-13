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

use Jose\Component\KeyManagement;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;

return function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(KeyManagement\JKUFactory::class)
        ->public()
        ->args([
            ref('jose.http_client'),
            ref('jose.request_factory'),
        ])
    ;

    $container->set(KeyManagement\X5UFactory::class)
        ->public()
        ->args([
            ref('jose.http_client'),
            ref('jose.request_factory'),
        ])
    ;
};

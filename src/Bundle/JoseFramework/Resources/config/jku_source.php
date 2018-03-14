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

use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\X5UFactory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(JKUFactory::class)
        ->args([
            ref('Jose\Component\Core\Converter\JsonConverter'),
            ref('jose.http_client'),
            ref('jose.request_factory'),
        ])
        ->public();
    $container->set(X5UFactory::class)
        ->args([
            ref('Jose\Component\Core\Converter\JsonConverter'),
            ref('jose.http_client'),
            ref('jose.request_factory'),
        ])
        ->public();
};

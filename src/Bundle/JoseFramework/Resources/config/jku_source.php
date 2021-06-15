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
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $serviceClosure = static function (string $serviceId): ReferenceConfigurator {
        return function_exists('Symfony\Component\DependencyInjection\Loader\Configurator\service')
            ? service($serviceId)
            : ref($serviceId);
    };

    $container->set(KeyManagement\JKUFactory::class)
        ->public()
        ->args([
            ($serviceClosure)('jose.http_client'),
            ($serviceClosure)('jose.request_factory'),
        ])
    ;

    $container->set(KeyManagement\X5UFactory::class)
        ->public()
        ->args([
            ($serviceClosure)('jose.http_client'),
            ($serviceClosure)('jose.request_factory'),
        ])
    ;
};

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

use Jose\Component\Signature\Algorithm;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * ---- New algorithms ----
 * These algorithms are out of the main specifications but referenced in
 * some WebAuthn documents.
 *
 * They may be subject to changes.
 * ------------------------
 */
return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(Algorithm\RS1::class)
        ->tag('jose.algorithm', ['alias' => 'RS1'])
    ;

    $container->set(Algorithm\HS1::class)
        ->tag('jose.algorithm', ['alias' => 'HS1'])
    ;

    $container->set(Algorithm\HS256_64::class)
        ->tag('jose.algorithm', ['alias' => 'HS256/64'])
    ;

    $container->set(Algorithm\ES256K::class)
        ->tag('jose.algorithm', ['alias' => 'ES256K'])
    ;
};

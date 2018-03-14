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

use Jose\Component\Signature\Algorithm;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(Algorithm\ES256::class)
        ->tag('jose.algorithm', ['alias' => 'ES256']);
    $container->set(Algorithm\ES384::class)
        ->tag('jose.algorithm', ['alias' => 'ES384']);
    $container->set(Algorithm\ES512::class)
        ->tag('jose.algorithm', ['alias' => 'ES512']);

    $container->set(Algorithm\RS256::class)
        ->tag('jose.algorithm', ['alias' => 'RS256']);
    $container->set(Algorithm\RS384::class)
        ->tag('jose.algorithm', ['alias' => 'RS384']);
    $container->set(Algorithm\RS512::class)
        ->tag('jose.algorithm', ['alias' => 'RS512']);

    $container->set(Algorithm\PS256::class)
        ->tag('jose.algorithm', ['alias' => 'PS256']);
    $container->set(Algorithm\PS384::class)
        ->tag('jose.algorithm', ['alias' => 'PS384']);
    $container->set(Algorithm\PS512::class)
        ->tag('jose.algorithm', ['alias' => 'PS512']);

    $container->set(Algorithm\HS256::class)
        ->tag('jose.algorithm', ['alias' => 'HS256']);
    $container->set(Algorithm\HS384::class)
        ->tag('jose.algorithm', ['alias' => 'HS384']);
    $container->set(Algorithm\HS512::class)
        ->tag('jose.algorithm', ['alias' => 'HS512']);

    $container->set(Algorithm\EdDSA::class)
        ->tag('jose.algorithm', ['alias' => 'EdDSA']);

    $container->set(Algorithm\None::class)
        ->tag('jose.algorithm', ['alias' => 'none']);
};

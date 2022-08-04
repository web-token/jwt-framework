<?php

declare(strict_types=1);

use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;

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

    $container->set(RS256::class)
        ->tag('jose.algorithm', [
            'alias' => 'RS256',
        ]);

    $container->set(RS384::class)
        ->tag('jose.algorithm', [
            'alias' => 'RS384',
        ]);

    $container->set(RS512::class)
        ->tag('jose.algorithm', [
            'alias' => 'RS512',
        ]);

    $container->set(PS256::class)
        ->tag('jose.algorithm', [
            'alias' => 'PS256',
        ]);

    $container->set(PS384::class)
        ->tag('jose.algorithm', [
            'alias' => 'PS384',
        ]);

    $container->set(PS512::class)
        ->tag('jose.algorithm', [
            'alias' => 'PS512',
        ]);
};

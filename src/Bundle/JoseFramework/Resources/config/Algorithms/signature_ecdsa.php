<?php

declare(strict_types=1);

use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;

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

    $container->set(ES256::class)
        ->tag('jose.algorithm', [
            'alias' => 'ES256',
        ]);

    $container->set(ES384::class)
        ->tag('jose.algorithm', [
            'alias' => 'ES384',
        ]);

    $container->set(ES512::class)
        ->tag('jose.algorithm', [
            'alias' => 'ES512',
        ]);
};

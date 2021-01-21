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

use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(ContentEncryption\A128CBCHS256::class)
        ->tag('jose.algorithm', ['alias' => 'A128CBC-HS256'])
    ;

    $container->set(ContentEncryption\A192CBCHS384::class)
        ->tag('jose.algorithm', ['alias' => 'A192CBC-HS384'])
    ;

    $container->set(ContentEncryption\A256CBCHS512::class)
        ->tag('jose.algorithm', ['alias' => 'A256CBC-HS512'])
    ;
};

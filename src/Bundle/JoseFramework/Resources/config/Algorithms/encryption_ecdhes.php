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

use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(KeyEncryption\ECDHES::class)
        ->tag('jose.algorithm', ['alias' => 'ECDH-ES'])
    ;

    $container->set(KeyEncryption\ECDHESA128KW::class)
        ->tag('jose.algorithm', ['alias' => 'ECDH-ES+A128KW'])
    ;

    $container->set(KeyEncryption\ECDHESA192KW::class)
        ->tag('jose.algorithm', ['alias' => 'ECDH-ES+A192KW'])
    ;

    $container->set(KeyEncryption\ECDHESA256KW::class)
        ->tag('jose.algorithm', ['alias' => 'ECDH-ES+A256KW'])
    ;
};

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

return function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(KeyEncryption\RSA15::class)
        ->tag('jose.algorithm', ['alias' => 'RSA1_5'])
    ;

    $container->set(KeyEncryption\RSAOAEP::class)
        ->tag('jose.algorithm', ['alias' => 'RSA-OAEP'])
    ;

    $container->set(KeyEncryption\RSAOAEP256::class)
        ->tag('jose.algorithm', ['alias' => 'RSA-OAEP-256'])
    ;
};

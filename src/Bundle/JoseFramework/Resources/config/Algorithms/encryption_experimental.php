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
use Jose\Component\Encryption\Algorithm\KeyEncryption;
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

    $container->set(KeyEncryption\A128CTR::class)
        ->tag('jose.algorithm', ['alias' => 'A128CTR'])
    ;

    $container->set(KeyEncryption\A192CTR::class)
        ->tag('jose.algorithm', ['alias' => 'A192CTR'])
    ;

    $container->set(KeyEncryption\A256CTR::class)
        ->tag('jose.algorithm', ['alias' => 'A256CTR'])
    ;

    $container->set(KeyEncryption\RSAOAEP384::class)
        ->tag('jose.algorithm', ['alias' => 'RSA-OAEP-384'])
    ;

    $container->set(KeyEncryption\RSAOAEP512::class)
        ->tag('jose.algorithm', ['alias' => 'RSA-OAEP-512'])
    ;

    $container->set(ContentEncryption\A128CCM_16_64::class)
        ->tag('jose.algorithm', ['alias' => 'A128CCM-16-64'])
    ;

    $container->set(ContentEncryption\A128CCM_16_128::class)
        ->tag('jose.algorithm', ['alias' => 'A128CCM-16-128'])
    ;

    $container->set(ContentEncryption\A128CCM_64_64::class)
        ->tag('jose.algorithm', ['alias' => 'A128CCM-64-64'])
    ;

    $container->set(ContentEncryption\A128CCM_64_128::class)
        ->tag('jose.algorithm', ['alias' => 'A128CCM-64-128'])
    ;

    $container->set(ContentEncryption\A256CCM_16_64::class)
        ->tag('jose.algorithm', ['alias' => 'A256CCM-16-64'])
    ;

    $container->set(ContentEncryption\A256CCM_16_128::class)
        ->tag('jose.algorithm', ['alias' => 'A256CCM-16-128'])
    ;

    $container->set(ContentEncryption\A256CCM_64_64::class)
        ->tag('jose.algorithm', ['alias' => 'A256CCM-64-64'])
    ;

    $container->set(ContentEncryption\A256CCM_64_128::class)
        ->tag('jose.algorithm', ['alias' => 'A256CCM-64-128'])
    ;
};

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

use Jose\Bundle\JoseFramework\Services;
use Jose\Component\Checker;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(Services\HeaderCheckerManagerFactory::class)
        ->public()
    ;

    $container->set(Services\ClaimCheckerManagerFactory::class)
        ->public()
    ;

    $container->set(Checker\ExpirationTimeChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'exp'])
    ;

    $container->set(Checker\IssuedAtChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'iat'])
    ;

    $container->set(Checker\NotBeforeChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'nbf'])
    ;
};

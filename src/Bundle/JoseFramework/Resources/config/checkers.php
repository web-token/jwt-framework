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

use Jose\Component\Checker;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(Checker\HeaderCheckerManagerFactory::class)
        ->public();

    $container->set(Checker\ClaimCheckerManagerFactory::class)
        ->public();

    $container->set(Checker\ExpirationTimeChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'exp']);

    $container->set(Checker\IssuedAtChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'iat']);

    $container->set(Checker\NotBeforeChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'nbf']);
};

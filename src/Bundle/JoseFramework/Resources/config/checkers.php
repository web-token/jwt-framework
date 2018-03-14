<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(HeaderCheckerManagerFactory::class)
        ->public();
    $container->set(ClaimCheckerManagerFactory::class)
        ->public();

    $container->set(ExpirationTimeChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'exp']);

    $container->set(IssuedAtChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'iat']);

    $container->set(NotBeforeChecker::class)
        ->tag('jose.checker.claim', ['alias' => 'nbf']);
};


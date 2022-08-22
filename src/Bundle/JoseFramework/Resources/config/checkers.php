<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;

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

    $container->set(HeaderCheckerManagerFactory::class)
        ->public();

    $container->set(ClaimCheckerManagerFactory::class)
        ->public();

    $container->set(ExpirationTimeChecker::class)
        ->tag('jose.checker.claim', [
            'alias' => 'exp',
        ])
        ->tag('jose.checker.header', [
            'alias' => 'exp',
        ]);

    $container->set(IssuedAtChecker::class)
        ->tag('jose.checker.claim', [
            'alias' => 'iat',
        ])
        ->tag('jose.checker.header', [
            'alias' => 'iat',
        ]);

    $container->set(NotBeforeChecker::class)
        ->tag('jose.checker.claim', [
            'alias' => 'nbf',
        ])
        ->tag('jose.checker.header', [
            'alias' => 'nbf',
        ]);
};

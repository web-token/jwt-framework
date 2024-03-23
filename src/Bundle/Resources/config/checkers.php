<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

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
        ->arg('$clock', service(ClockInterface::class))
        ->tag('jose.checker.claim', [
            'alias' => 'exp',
        ])
        ->tag('jose.checker.header', [
            'alias' => 'exp',
        ]);

    $container->set(IssuedAtChecker::class)
        ->arg('$clock', service(ClockInterface::class))
        ->tag('jose.checker.claim', [
            'alias' => 'iat',
        ])
        ->tag('jose.checker.header', [
            'alias' => 'iat',
        ]);

    $container->set(NotBeforeChecker::class)
        ->arg('$clock', service(ClockInterface::class))
        ->tag('jose.checker.claim', [
            'alias' => 'nbf',
        ])
        ->tag('jose.checker.header', [
            'alias' => 'nbf',
        ]);
};

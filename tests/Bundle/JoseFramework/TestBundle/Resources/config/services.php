<?php

declare(strict_types=1);

use Jose\Tests\Bundle\JoseFramework\TestBundle\Checker\CustomChecker;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(CustomChecker::class)
        ->tag('jose.checker.header', [
            'alias' => 'custom_checker',
        ])
        ->tag('jose.checker.claim', [
            'alias' => 'custom_checker',
        ]);

    $container->set(ClockInterface::class)
        ->class(NativeClock::class)
    ;
};

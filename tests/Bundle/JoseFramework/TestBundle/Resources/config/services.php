<?php

declare(strict_types=1);

use Jose\Component\Checker\CallableChecker;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Checker\CustomChecker;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Checker\MaximumLifetime;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Service\DeprecatedES256KConsumer;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Service\NestedTokenServiceConsumer;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Service\SelectiveDisclosureServiceConsumer;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

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

    $container->set(MaximumLifetime::class);

    $container->set('jose.test.claim_checker.max_lifetime', CallableChecker::class)
        ->args(['exp', service(MaximumLifetime::class)])
        ->tag('jose.checker.claim', [
            'alias' => 'max_lifetime',
        ]);

    $container->set(ClockInterface::class)
        ->class(NativeClock::class)
    ;

    $container->set(NestedTokenServiceConsumer::class)
        ->public()
    ;

    $container->set(SelectiveDisclosureServiceConsumer::class)
        ->public()
    ;

    $container->set(DeprecatedES256KConsumer::class)
        ->public()
    ;
};

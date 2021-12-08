<?php

declare(strict_types=1);

use Jose\Tests\Bundle\JoseFramework\TestBundle\Checker\CustomChecker;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(CustomChecker::class)
        ->tag('jose.checker.header', [
            'alias' => 'custom_checker',
        ])
        ->tag('jose.checker.claim', [
            'alias' => 'custom_checker',
        ])
    ;
};

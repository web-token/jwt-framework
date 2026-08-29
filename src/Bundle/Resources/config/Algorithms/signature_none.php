<?php

declare(strict_types=1);

use Jose\Unsecured\Signature\None;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(None::class)
        ->tag('jose.algorithm', [
            'alias' => 'none',
        ]);
};

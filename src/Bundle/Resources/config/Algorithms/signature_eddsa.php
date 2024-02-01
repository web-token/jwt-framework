<?php

declare(strict_types=1);

use Jose\Component\Signature\Algorithm\EdDSA;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(EdDSA::class)
        ->tag('jose.algorithm', [
            'alias' => 'EdDSA',
        ]);
};

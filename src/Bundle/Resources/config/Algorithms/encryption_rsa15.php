<?php

declare(strict_types=1);

use Jose\Rsa15\KeyEncryption\RSA15;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(RSA15::class)
        ->tag('jose.algorithm', [
            'alias' => 'RSA1_5',
        ]);
};

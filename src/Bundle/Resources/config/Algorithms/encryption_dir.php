<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(Dir::class)
        ->tag('jose.algorithm', [
            'alias' => 'dir',
        ]);
};

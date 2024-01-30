<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
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

    $container->set(RSAOAEP::class)
        ->tag('jose.algorithm', [
            'alias' => 'RSA-OAEP',
        ]);

    $container->set(RSAOAEP256::class)
        ->tag('jose.algorithm', [
            'alias' => 'RSA-OAEP-256',
        ]);
};

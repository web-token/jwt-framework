<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15 as LibraryRSA15;
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

    $container->set(LibraryRSA15::class)
        ->deprecate(
            'web-token/jwt-framework',
            '4.3.0',
            'The "%service_id%" service is deprecated and will be removed in 5.0.0: the "RSA1_5" algorithm is now shipped by the "web-token/jwt-rsa15" package and registered as "' . RSA15::class . '", under the same "RSA1_5" alias.'
        );
};

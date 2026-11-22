<?php

declare(strict_types=1);

use Jose\Component\Signature\Algorithm\None as LibraryNone;
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

    $container->set(LibraryNone::class)
        ->deprecate(
            'web-token/jwt-framework',
            '4.3.0',
            'The "%service_id%" service is deprecated and will be removed in 5.0.0: the "none" algorithm is now shipped by the "web-token/jwt-unsecured" package and registered as "' . None::class . '", under the same "none" alias.'
        );
};

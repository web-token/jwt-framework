<?php

declare(strict_types=1);

use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\Compression\Deflate;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(CompressionMethodManagerFactory::class)
        ->deprecate(
            'web-token/jwt-bundle',
            '3.3.0',
            'The "%service_id%" service is deprecated and will be removed in version 4.0. Compression is not recommended for the JWE.'
        )
        ->public();

    $container->set(Deflate::class)
        ->deprecate(
            'web-token/jwt-bundle',
            '3.3.0',
            'The "%service_id%" service is deprecated and will be removed in version 4.0. Compression is not recommended for the JWE.'
        )
        ->tag('jose.compression_method', [
            'alias' => 'DEF',
        ]);
};

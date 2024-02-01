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
        ->public();

    $container->set(Deflate::class)
        ->tag('jose.compression_method', [
            'alias' => 'DEF',
        ]);
};

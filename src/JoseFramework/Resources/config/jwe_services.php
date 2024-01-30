<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Bundle\JoseFramework\Services\JWEDecrypterFactory;
use Jose\Bundle\JoseFramework\Services\JWELoaderFactory;
use Jose\Component\Encryption\JWETokenSupport;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(JWEBuilderFactory::class)
        ->public();

    $container->set(JWEDecrypterFactory::class)
        ->public();

    $container->set(JWELoaderFactory::class)
        ->public();

    $container->set(JWETokenSupport::class);
};

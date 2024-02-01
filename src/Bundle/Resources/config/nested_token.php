<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\Services\NestedTokenBuilderFactory;
use Jose\Bundle\JoseFramework\Services\NestedTokenLoaderFactory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(NestedTokenBuilderFactory::class)
        ->public();

    $container->set(NestedTokenLoaderFactory::class)
        ->public();
};

<?php

declare(strict_types=1);

use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\X5UFactory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    if (interface_exists(HttpClientInterface::class)) {
        $container->set(JKUFactory::class)
            ->public()
            ->args([service('jose.http_client')]);

        $container->set(X5UFactory::class)
            ->public()
            ->args([service('jose.http_client')]);
    }
};

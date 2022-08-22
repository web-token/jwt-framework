<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\Controller\JWKSetControllerFactory;
use Jose\Bundle\JoseFramework\Routing\JWKSetLoader;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(JWKSetControllerFactory::class);

    $container->set(JWKSetLoader::class)
        ->tag('routing.loader');
};

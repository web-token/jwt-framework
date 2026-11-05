<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\Services\SDJWTHolderFactory;
use Jose\Bundle\JoseFramework\Services\SDJWTIssuerFactory;
use Jose\Bundle\JoseFramework\Services\SDJWTVerifierFactory;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(SDJWTIssuerFactory::class)
        ->public();

    $container->set(SDJWTHolderFactory::class)
        ->arg('$clock', service(ClockInterface::class))
        ->public();

    $container->set(SDJWTVerifierFactory::class)
        ->arg('$clock', service(ClockInterface::class))
        ->public();
};

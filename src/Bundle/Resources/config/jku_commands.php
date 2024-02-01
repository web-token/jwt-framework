<?php

declare(strict_types=1);

use Jose\Component\Console\JKULoaderCommand;
use Jose\Component\Console\X5ULoaderCommand;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(JKULoaderCommand::class);
    $container->set(X5ULoaderCommand::class);
};

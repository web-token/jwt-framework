<?php

declare(strict_types=1);

use Jose\Bundle\JoseFramework\DataCollector\AlgorithmCollector;
use Jose\Bundle\JoseFramework\DataCollector\CheckerCollector;
use Jose\Bundle\JoseFramework\DataCollector\JoseCollector;
use Jose\Bundle\JoseFramework\DataCollector\JWECollector;
use Jose\Bundle\JoseFramework\DataCollector\JWSCollector;
use Jose\Bundle\JoseFramework\DataCollector\KeyCollector;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(JoseCollector::class)
        ->tag('data_collector', [
            'id' => 'jose_collector',
            'template' => '@JoseFramework/data_collector/template.html.twig',
        ]);

    $container->set(AlgorithmCollector::class);
    $container->set(CheckerCollector::class);
    $container->set(JWECollector::class);
    $container->set(JWSCollector::class);
    $container->set(KeyCollector::class);
};

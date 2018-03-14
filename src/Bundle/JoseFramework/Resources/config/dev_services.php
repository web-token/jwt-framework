<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Jose\Bundle\JoseFramework\DataCollector;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();


    $container->set(DataCollector\JoseCollector::class)
        ->tag('data_collector', [
                'template' => '@JoseFramework/data_collector/template.html.twig',
                'id'       => 'jose_collector',
        ]);

    $container->set(DataCollector\AlgorithmCollector::class);
    $container->set(DataCollector\CheckerCollector::class);
    $container->set(DataCollector\JWECollector::class);
    $container->set(DataCollector\JWSCollector::class);
    $container->set(DataCollector\KeyCollector::class);

};


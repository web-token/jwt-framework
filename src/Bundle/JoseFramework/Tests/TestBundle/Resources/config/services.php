<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Bundle\JoseFramework\Tests\TestBundle\Checker\CustomChecker;
use Jose\Bundle\JoseFramework\Tests\TestBundle\Converter\CustomJsonConverter;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(CustomJsonConverter::class);

    $container->set(CustomChecker::class)
        ->tag('jose.checker.header', ['alias' => 'custom_checker'])
        ->tag('jose.checker.claim', ['alias' => 'custom_checker'])
    ;
};

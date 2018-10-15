<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Component\Signature\Serializer;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(Serializer\JWSSerializerManagerFactory::class)
        ->public();

    $container->set(Serializer\CompactSerializer::class);
    $container->set(Serializer\JSONFlattenedSerializer::class);
    $container->set(Serializer\JSONGeneralSerializer::class);
};

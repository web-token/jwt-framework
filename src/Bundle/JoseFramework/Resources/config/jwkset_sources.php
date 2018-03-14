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

use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSetSource;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set('jose.jwk_set_source.jwkset')
        ->class(JWKSetSource\JWKSet::class)
        ->tag('jose.jwkset_source');

    $container->set('jose.jwk_set_source.jku')
        ->class(JWKSetSource\JKU::class)
        ->tag('jose.jwkset_source');

    $container->set('jose.jwk_set_source.x5u')
        ->class(JWKSetSource\X5U::class)
        ->tag('jose.jwkset_source');
};

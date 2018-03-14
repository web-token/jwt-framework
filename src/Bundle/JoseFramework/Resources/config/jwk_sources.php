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
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set('jose.jwk_source.keyfile')
        ->class(JWKSource\KeyFile::class)
        ->tag('jose.jwk_source' );

    $container->set('jose.jwk_source.certificatefile')
        ->class(JWKSource\CertificateFile::class)
        ->tag('jose.jwk_source');

    $container->set('jose.jwk_source.values')
        ->class(JWKSource\Values::class)
        ->tag('jose.jwk_source');

    $container->set('jose.jwk_source.secret')
        ->class(JWKSource\Secret::class)
        ->tag('jose.jwk_source');

    $container->set('jose.jwk_source.jwk')
        ->class(JWKSource\JWK::class)
        ->tag('jose.jwk_source');

    $container->set('jose.jwk_source.x5c')
        ->class(JWKSource\X5C::class)
        ->tag('jose.jwk_source');

    $container->set('jose.jwk_source.jwkset')
        ->class(JWKSource\JWKSet::class)
        ->tag('jose.jwk_source');
};

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

use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(ContentEncryption\A128CBCHS256::class)
        ->tag('jose.algorithm', ['alias' => 'A128CBC-HS256']);
    $container->set(ContentEncryption\A192CBCHS384::class)
        ->tag('jose.algorithm', ['alias' => 'A192CBC-HS384']);
    $container->set(ContentEncryption\A256CBCHS512::class)
        ->tag('jose.algorithm', ['alias' => 'A256CBC-HS512']);

    $container->set(ContentEncryption\A128GCM::class)
        ->tag('jose.algorithm', ['alias' => 'A128GCM']);
    $container->set(ContentEncryption\A192GCM::class)
        ->tag('jose.algorithm', ['alias' => 'A192GCM']);
    $container->set(ContentEncryption\A256GCM::class)
        ->tag('jose.algorithm', ['alias' => 'A256GCM']);

    $container->set(KeyEncryption\A128GCMKW::class)
        ->tag('jose.algorithm', ['alias' => 'A128GCMKW']);
    $container->set(KeyEncryption\A192GCMKW::class)
        ->tag('jose.algorithm', ['alias' => 'A192GCMKW']);
    $container->set(KeyEncryption\A256GCMKW::class)
        ->tag('jose.algorithm', ['alias' => 'A256GCMKW']);

    $container->set(KeyEncryption\Dir::class)
        ->tag('jose.algorithm', ['alias' => 'dir']);

    $container->set(KeyEncryption\ECDHES::class)
        ->tag('jose.algorithm', ['alias' => 'ECDH-ES']);
    $container->set(KeyEncryption\ECDHESA128KW::class)
        ->tag('jose.algorithm', ['alias' => 'ECDH-ES+A128KW']);
    $container->set(KeyEncryption\ECDHESA192KW::class)
        ->tag('jose.algorithm', ['alias' => 'ECDH-ES+A192KW']);
    $container->set(KeyEncryption\ECDHESA256KW::class)
        ->tag('jose.algorithm', ['alias' => 'ECDH-ES+A256KW']);

    $container->set(KeyEncryption\A128KW::class)
        ->tag('jose.algorithm', ['alias' => 'A128KW']);
    $container->set(KeyEncryption\A192KW::class)
        ->tag('jose.algorithm', ['alias' => 'A192KW']);
    $container->set(KeyEncryption\A256KW::class)
        ->tag('jose.algorithm', ['alias' => 'A256KW']);

    $container->set(KeyEncryption\PBES2HS256A128KW::class)
        ->tag('jose.algorithm', ['alias' => 'PBES2-HS256+A128KW']);
    $container->set(KeyEncryption\PBES2HS384A192KW::class)
        ->tag('jose.algorithm', ['alias' => 'PBES2-HS384+A192KW']);
    $container->set(KeyEncryption\PBES2HS512A256KW::class)
        ->tag('jose.algorithm', ['alias' => 'PBES2-HS512+A256KW']);

    $container->set(KeyEncryption\RSA15::class)
        ->tag('jose.algorithm', ['alias' => 'RSA1_5']);
    $container->set(KeyEncryption\RSAOAEP::class)
        ->tag('jose.algorithm', ['alias' => 'RSA-OAEP']);
    $container->set(KeyEncryption\RSAOAEP256::class)
        ->tag('jose.algorithm', ['alias' => 'RSA-OAEP-256']);

    // ---- New algorithms ----
    // These algorithms are out of the main specifications but referenced in
    // some WebAuthn documents.
    //
    // They may be subject to changes.
    // ------------------------

    $container->set(KeyEncryption\Chacha20Poly1305::class)
        ->tag('jose.algorithm', ['alias' => 'chacha20-poly1305']);

    $container->set(KeyEncryption\A128CTR::class)
        ->tag('jose.algorithm', ['alias' => 'A128CTR']);
    $container->set(KeyEncryption\A192CTR::class)
        ->tag('jose.algorithm', ['alias' => 'A192CTR']);
    $container->set(KeyEncryption\A256CTR::class)
        ->tag('jose.algorithm', ['alias' => 'A256CTR']);

    $container->set(KeyEncryption\RSAOAEP384::class)
        ->tag('jose.algorithm', ['alias' => 'RSA-OAEP-384']);

    $container->set(KeyEncryption\RSAOAEP512::class)
        ->tag('jose.algorithm', ['alias' => 'RSA-OAEP-512']);

    $container->set(ContentEncryption\A128CCM_16_64::class)
        ->tag('jose.algorithm', ['alias' => 'A128CCM-16-64']);
    $container->set(ContentEncryption\A128CCM_16_128::class)
        ->tag('jose.algorithm', ['alias' => 'A128CCM-16-128']);
    $container->set(ContentEncryption\A128CCM_64_64::class)
        ->tag('jose.algorithm', ['alias' => 'A128CCM-64-64']);
    $container->set(ContentEncryption\A128CCM_64_128::class)
        ->tag('jose.algorithm', ['alias' => 'A128CCM-64-128']);

    $container->set(ContentEncryption\A256CCM_16_64::class)
        ->tag('jose.algorithm', ['alias' => 'A256CCM-16-64']);
    $container->set(ContentEncryption\A256CCM_16_128::class)
        ->tag('jose.algorithm', ['alias' => 'A256CCM-16-256']);
    $container->set(ContentEncryption\A256CCM_64_64::class)
        ->tag('jose.algorithm', ['alias' => 'A256CCM-64-64']);
    $container->set(ContentEncryption\A256CCM_64_128::class)
        ->tag('jose.algorithm', ['alias' => 'A256CCM-64-256']);
};

<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(A128CBCHS256::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128CBC-HS256',
        ]);

    $container->set(A192CBCHS384::class)
        ->tag('jose.algorithm', [
            'alias' => 'A192CBC-HS384',
        ]);

    $container->set(A256CBCHS512::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256CBC-HS512',
        ]);
};

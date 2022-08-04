<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;

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

    $container->set(A128GCMKW::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128GCMKW',
        ]);

    $container->set(A192GCMKW::class)
        ->tag('jose.algorithm', [
            'alias' => 'A192GCMKW',
        ]);

    $container->set(A256GCMKW::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256GCMKW',
        ]);
};

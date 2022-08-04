<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;

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

    $container->set(A128KW::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128KW',
        ]);

    $container->set(A192KW::class)
        ->tag('jose.algorithm', [
            'alias' => 'A192KW',
        ]);

    $container->set(A256KW::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256KW',
        ]);
};

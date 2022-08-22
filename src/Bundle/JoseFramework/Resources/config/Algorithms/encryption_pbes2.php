<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;

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

    $container->set(PBES2HS256A128KW::class)
        ->tag('jose.algorithm', [
            'alias' => 'PBES2-HS256+A128KW',
        ]);

    $container->set(PBES2HS384A192KW::class)
        ->tag('jose.algorithm', [
            'alias' => 'PBES2-HS384+A192KW',
        ]);

    $container->set(PBES2HS512A256KW::class)
        ->tag('jose.algorithm', [
            'alias' => 'PBES2-HS512+A256KW',
        ]);
};

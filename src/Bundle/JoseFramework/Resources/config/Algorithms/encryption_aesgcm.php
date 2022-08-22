<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;

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

    $container->set(A128GCM::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128GCM',
        ]);

    $container->set(A192GCM::class)
        ->tag('jose.algorithm', [
            'alias' => 'A192GCM',
        ]);

    $container->set(A256GCM::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256GCM',
        ]);
};

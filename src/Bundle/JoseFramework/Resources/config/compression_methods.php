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

use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Compression\GZip;
use Jose\Component\Encryption\Compression\ZLib;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(CompressionMethodManagerFactory::class)
        ->public();

    $container->set(Deflate::class)
        ->tag('jose.compression_method', ['alias' => 'DEF']);
    $container->set(GZip::class)
        ->tag('jose.compression_method', ['alias' => 'GZ']);
    $container->set(ZLib::class)
        ->tag('jose.compression_method', ['alias' => 'ZLIB']);
};

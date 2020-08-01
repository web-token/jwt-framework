<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Component\Console;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(Console\AddKeyIntoKeysetCommand::class);
    $container->set(Console\EcKeyGeneratorCommand::class);
    $container->set(Console\EcKeysetGeneratorCommand::class);
    $container->set(Console\GetThumbprintCommand::class);
    $container->set(Console\OptimizeRsaKeyCommand::class);
    $container->set(Console\KeyAnalyzerCommand::class);
    $container->set(Console\KeyFileLoaderCommand::class);
    $container->set(Console\KeysetAnalyzerCommand::class);
    $container->set(Console\MergeKeysetCommand::class);
    $container->set(Console\NoneKeyGeneratorCommand::class);
    $container->set(Console\OctKeyGeneratorCommand::class);
    $container->set(Console\OctKeysetGeneratorCommand::class);
    $container->set(Console\OkpKeyGeneratorCommand::class);
    $container->set(Console\OkpKeysetGeneratorCommand::class);
    $container->set(Console\P12CertificateLoaderCommand::class);
    $container->set(Console\PemConverterCommand::class);
    $container->set(Console\PublicKeyCommand::class);
    $container->set(Console\PublicKeysetCommand::class);
    $container->set(Console\RotateKeysetCommand::class);
    $container->set(Console\RsaKeyGeneratorCommand::class);
    $container->set(Console\RsaKeysetGeneratorCommand::class);
    $container->set(Console\SecretKeyGeneratorCommand::class);
    $container->set(Console\X509CertificateLoaderCommand::class);
};

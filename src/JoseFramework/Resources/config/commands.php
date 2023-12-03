<?php

declare(strict_types=1);

use Jose\Component\Console\AddKeyIntoKeysetCommand;
use Jose\Component\Console\EcKeyGeneratorCommand;
use Jose\Component\Console\EcKeysetGeneratorCommand;
use Jose\Component\Console\GetThumbprintCommand;
use Jose\Component\Console\KeyAnalyzerCommand;
use Jose\Component\Console\KeyFileLoaderCommand;
use Jose\Component\Console\KeysetAnalyzerCommand;
use Jose\Component\Console\MergeKeysetCommand;
use Jose\Component\Console\NoneKeyGeneratorCommand;
use Jose\Component\Console\OctKeyGeneratorCommand;
use Jose\Component\Console\OctKeysetGeneratorCommand;
use Jose\Component\Console\OkpKeyGeneratorCommand;
use Jose\Component\Console\OkpKeysetGeneratorCommand;
use Jose\Component\Console\OptimizeRsaKeyCommand;
use Jose\Component\Console\P12CertificateLoaderCommand;
use Jose\Component\Console\PemConverterCommand;
use Jose\Component\Console\PublicKeyCommand;
use Jose\Component\Console\PublicKeysetCommand;
use Jose\Component\Console\RotateKeysetCommand;
use Jose\Component\Console\RsaKeyGeneratorCommand;
use Jose\Component\Console\RsaKeysetGeneratorCommand;
use Jose\Component\Console\SecretKeyGeneratorCommand;
use Jose\Component\Console\X509CertificateLoaderCommand;

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

    $container->set(AddKeyIntoKeysetCommand::class);
    $container->set(EcKeyGeneratorCommand::class);
    $container->set(EcKeysetGeneratorCommand::class);
    $container->set(GetThumbprintCommand::class);
    $container->set(OptimizeRsaKeyCommand::class);
    $container->set(KeyAnalyzerCommand::class);
    $container->set(KeyFileLoaderCommand::class);
    $container->set(KeysetAnalyzerCommand::class);
    $container->set(MergeKeysetCommand::class);
    $container->set(NoneKeyGeneratorCommand::class);
    $container->set(OctKeyGeneratorCommand::class);
    $container->set(OctKeysetGeneratorCommand::class);
    $container->set(OkpKeyGeneratorCommand::class);
    $container->set(OkpKeysetGeneratorCommand::class);
    $container->set(P12CertificateLoaderCommand::class);
    $container->set(PemConverterCommand::class);
    $container->set(PublicKeyCommand::class);
    $container->set(PublicKeysetCommand::class);
    $container->set(RotateKeysetCommand::class);
    $container->set(RsaKeyGeneratorCommand::class);
    $container->set(RsaKeysetGeneratorCommand::class);
    $container->set(SecretKeyGeneratorCommand::class);
    $container->set(X509CertificateLoaderCommand::class);
};

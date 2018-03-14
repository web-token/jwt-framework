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

use Jose\Component\KeyManagement\KeyAnalyzer\AlgorithmAnalyzer;
use Jose\Component\KeyManagement\KeyAnalyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\KeyAnalyzer\KeyIdentifierAnalyzer;
use Jose\Component\KeyManagement\KeyAnalyzer\NoneAnalyzer;
use Jose\Component\KeyManagement\KeyAnalyzer\OctAnalyzer;
use Jose\Component\KeyManagement\KeyAnalyzer\RsaAnalyzer;
use Jose\Component\KeyManagement\KeyAnalyzer\UsageAnalyzer;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(KeyAnalyzerManager::class);
    $container->set(AlgorithmAnalyzer::class);
    $container->set(UsageAnalyzer::class);
    $container->set(KeyIdentifierAnalyzer::class);
    $container->set(NoneAnalyzer::class);
    $container->set(OctAnalyzer::class);
    $container->set(RsaAnalyzer::class);
};

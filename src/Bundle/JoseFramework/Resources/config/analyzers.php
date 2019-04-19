<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Component\KeyManagement\Analyzer;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container) {
    $container = $container->services()->defaults()
        ->private()
        ->autoconfigure()
        ->autowire()
    ;

    $container->set(Analyzer\KeyAnalyzerManager::class)
        ->public()
    ;

    $container->set(Analyzer\KeysetAnalyzerManager::class)
        ->public()
    ;

    $container->set(Analyzer\AlgorithmAnalyzer::class);
    $container->set(Analyzer\UsageAnalyzer::class);
    $container->set(Analyzer\KeyIdentifierAnalyzer::class);
    $container->set(Analyzer\NoneAnalyzer::class);
    $container->set(Analyzer\OctAnalyzer::class);

    $container->set(Analyzer\MixedKeyTypes::class);
    $container->set(Analyzer\MixedPublicAndPrivateKeys::class);
};

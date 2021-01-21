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

use Jose\Component\Core\Util\Ecc\NistCurve;
use Jose\Component\KeyManagement\Analyzer;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use ZxcvbnPhp\Zxcvbn;

return function (ContainerConfigurator $container): void {
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
    $container->set(Analyzer\HS256KeyAnalyzer::class);
    $container->set(Analyzer\HS384KeyAnalyzer::class);
    $container->set(Analyzer\HS512KeyAnalyzer::class);

    if (class_exists(NistCurve::class)) {
        $container->set(Analyzer\ES256KeyAnalyzer::class);
        $container->set(Analyzer\ES384KeyAnalyzer::class);
        $container->set(Analyzer\ES512KeyAnalyzer::class);
    }

    if (class_exists(Zxcvbn::class)) {
        $container->set(Analyzer\ZxcvbnKeyAnalyzer::class);
    }
};

<?php

declare(strict_types=1);

use Jose\Component\Core\Util\Ecc\NistCurve;
use Jose\Component\KeyManagement\Analyzer\AlgorithmAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES256KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES384KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES512KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS256KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS384KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\HS512KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeyIdentifierAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\MixedKeyTypes;
use Jose\Component\KeyManagement\Analyzer\MixedPublicAndPrivateKeys;
use Jose\Component\KeyManagement\Analyzer\NoneAnalyzer;
use Jose\Component\KeyManagement\Analyzer\OctAnalyzer;
use Jose\Component\KeyManagement\Analyzer\UsageAnalyzer;

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Component\KeyManagement\Analyzer\ZxcvbnKeyAnalyzer;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use ZxcvbnPhp\Zxcvbn;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(KeyAnalyzerManager::class)
        ->public();

    $container->set(KeysetAnalyzerManager::class)
        ->public();

    $container->set(AlgorithmAnalyzer::class);
    $container->set(UsageAnalyzer::class);
    $container->set(KeyIdentifierAnalyzer::class);
    $container->set(NoneAnalyzer::class);
    $container->set(OctAnalyzer::class);
    $container->set(MixedKeyTypes::class);
    $container->set(MixedPublicAndPrivateKeys::class);
    $container->set(HS256KeyAnalyzer::class);
    $container->set(HS384KeyAnalyzer::class);
    $container->set(HS512KeyAnalyzer::class);

    if (class_exists(NistCurve::class)) {
        $container->set(ES256KeyAnalyzer::class);
        $container->set(ES384KeyAnalyzer::class);
        $container->set(ES512KeyAnalyzer::class);
    }

    if (class_exists(Zxcvbn::class)) {
        $container->set(ZxcvbnKeyAnalyzer::class);
    }
};

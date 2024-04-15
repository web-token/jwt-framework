<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Doctrine\Set\DoctrineSetList;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Set\SymfonySetList;
use Rector\ValueObject\PhpVersion;

return static function (RectorConfig $config): void {
    $config->import(SetList::DEAD_CODE);
    $config->import(LevelSetList::UP_TO_PHP_83);
    $config->import(SymfonySetList::SYMFONY_64);
    $config->import(SymfonySetList::SYMFONY_50_TYPES);
    $config->import(SymfonySetList::SYMFONY_52_VALIDATOR_ATTRIBUTES);
    $config->import(SymfonySetList::SYMFONY_CODE_QUALITY);
    $config->import(SymfonySetList::SYMFONY_CONSTRUCTOR_INJECTION);
    $config->import(SymfonySetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(DoctrineSetList::DOCTRINE_CODE_QUALITY);
    $config->import(DoctrineSetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(PHPUnitSetList::PHPUNIT_CODE_QUALITY);
    $config->import(PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES);
    $config->import(PHPUnitSetList::PHPUNIT_100);
    $config->paths([
        __DIR__ . '/ecs.php',
        __DIR__ . '/rector.php',
        __DIR__ . '/performance',
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ]);
    $config->skip([
        PreferPHPUnitThisCallRector::class => __DIR__ . '/tests',
        __DIR__ . '/src/Library/Core/JWKSet.php',
        __DIR__ . '/src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSource.php',
        __DIR__ . '/src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSetSource.php',
    ]);
    $config->phpVersion(PhpVersion::PHP_83);
    $config->parallel();
    $config->importNames();
    $config->importShortClasses();
};

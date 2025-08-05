<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Doctrine\Set\DoctrineSetList;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Symfony73\Rector\Class_\InvokableCommandInputAttributeRector;
use Rector\ValueObject\PhpVersion;

$builder = RectorConfig::configure();
if (file_exists('/tools/.composer/vendor-bin/phpunit/vendor/autoload.php')) {
    $builder->withAutoloadPaths(['/tools/.composer/vendor-bin/phpunit/vendor/autoload.php']);
}
$builder->withSets([
    SetList::DEAD_CODE,
    LevelSetList::UP_TO_PHP_82,
    DoctrineSetList::DOCTRINE_CODE_QUALITY,
    DoctrineSetList::ANNOTATIONS_TO_ATTRIBUTES,
    PHPUnitSetList::PHPUNIT_CODE_QUALITY,
    PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES,
    PHPUnitSetList::PHPUNIT_120,
]);
$builder->withComposerBased(twig: true, doctrine: true, phpunit: true, symfony: true);
$builder->withPhpVersion(PhpVersion::PHP_82);
$builder->withPaths(
    [
        __DIR__ . '/../src',
        __DIR__ . '/../tests',
        __DIR__ . '/../castor.php',
        __DIR__ . '/../performance',
        __DIR__ . '/ecs.php',
        __DIR__ . '/rector.php',
    ]
);
$builder->withSkip([
    InvokableCommandInputAttributeRector::class,
    PreferPHPUnitThisCallRector::class,
    __DIR__ . '/../src/Library/Core/JWKSet.php',
    __DIR__ . '/../src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSource.php',
    __DIR__ . '/../src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSetSource.php',
]);
$builder->withParallel();
$builder->withImportNames();

return $builder;

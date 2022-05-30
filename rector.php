<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Core\ValueObject\PhpVersion;
use Rector\Php74\Rector\Property\TypedPropertyRector;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Set\SymfonyLevelSetList;
use Rector\Symfony\Set\SymfonySetList;

return static function (RectorConfig $config): void {
    $config->import(SetList::DEAD_CODE);
    $config->import(LevelSetList::UP_TO_PHP_81);
    $config->import(SymfonyLevelSetList::UP_TO_SYMFONY_54);
    $config->import(SymfonySetList::SYMFONY_CODE_QUALITY);
    $config->parallel();
    $config->paths([__DIR__ . '/src', __DIR__ . '/performance', __DIR__ . '/tests']);
    $config->skip([
        __DIR__ . '/src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSource.php',
        __DIR__ . '/src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSetSource.php',
    ]);
    $config->phpVersion(PhpVersion::PHP_81);
    $config->importNames();
    $config->importShortClasses();

    $services = $config->services();
    $services->set(TypedPropertyRector::class);
};

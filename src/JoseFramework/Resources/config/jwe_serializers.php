<?php

declare(strict_types=1);

use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(JWESerializerManagerFactory::class)
        ->public();

    $container->set(CompactSerializer::class);
    $container->set(JSONFlattenedSerializer::class);
    $container->set(JSONGeneralSerializer::class);
};

<?php

declare(strict_types=1);

use AESKW\Wrapper;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSS;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA256KW;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(ECDHES::class)
        ->tag('jose.algorithm', [
            'alias' => 'ECDH-ES',
        ]);

    $container->set(ECDHSS::class)
        ->tag('jose.algorithm', [
            'alias' => 'ECDH-SS',
        ]);

    if (interface_exists(Wrapper::class)) {
        $container->set(ECDHESA128KW::class)
            ->tag('jose.algorithm', [
                'alias' => 'ECDH-ES+A128KW',
            ]);

        $container->set(ECDHESA192KW::class)
            ->tag('jose.algorithm', [
                'alias' => 'ECDH-ES+A192KW',
            ]);

        $container->set(ECDHESA256KW::class)
            ->tag('jose.algorithm', [
                'alias' => 'ECDH-ES+A256KW',
            ]);

        $container->set(ECDHSSA128KW::class)
            ->tag('jose.algorithm', [
                'alias' => 'ECDH-SS+A128KW',
            ]);

        $container->set(ECDHSSA192KW::class)
            ->tag('jose.algorithm', [
                'alias' => 'ECDH-SS+A192KW',
            ]);

        $container->set(ECDHSSA256KW::class)
            ->tag('jose.algorithm', [
                'alias' => 'ECDH-SS+A256KW',
            ]);
    }
};

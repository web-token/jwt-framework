<?php

declare(strict_types=1);

use Jose\Component\Signature\Algorithm\ES256K as StandardES256K;
use Jose\Experimental\Signature\Blake2b;
use Jose\Experimental\Signature\ES256K;
use Jose\Experimental\Signature\HS1;
use Jose\Experimental\Signature\HS256_64;
use Jose\Experimental\Signature\RS1;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * ---- New algorithms ----
 * These algorithms are out of the main specifications but referenced in
 * some WebAuthn documents.
 *
 * They may be subject to changes.
 * ------------------------
 */
return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(RS1::class)
        ->tag('jose.algorithm', [
            'alias' => 'RS1',
        ]);

    $container->set(HS1::class)
        ->tag('jose.algorithm', [
            'alias' => 'HS1',
        ]);

    $container->set(HS256_64::class)
        ->tag('jose.algorithm', [
            'alias' => 'HS256/64',
        ]);

    $container->set(ES256K::class)
        ->deprecate(
            'web-token/jwt-framework',
            '4.3.0',
            'The "%service_id%" service is deprecated: the "ES256K" algorithm moved to the library and is registered as "' . StandardES256K::class . '", under the same "ES256K" alias.'
        );

    $container->set(Blake2b::class)
        ->tag('jose.algorithm', [
            'alias' => 'BLAKE2B',
        ]);
};

<?php

declare(strict_types=1);

use Jose\Component\Signature\Algorithm\MLDSA44;
use Jose\Component\Signature\Algorithm\MLDSA65;
use Jose\Component\Signature\Algorithm\MLDSA87;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * Loaded only when the platform can run ML-DSA (PHP 8.4 and an OpenSSL runtime providing it): the algorithm manager
 * factory instantiates every tagged algorithm when the container is built, and an unsupported one would throw there.
 */
return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $container->set(MLDSA44::class)
        ->tag('jose.algorithm', [
            'alias' => 'ML-DSA-44',
        ]);
    $container->set(MLDSA65::class)
        ->tag('jose.algorithm', [
            'alias' => 'ML-DSA-65',
        ]);
    $container->set(MLDSA87::class)
        ->tag('jose.algorithm', [
            'alias' => 'ML-DSA-87',
        ]);
};

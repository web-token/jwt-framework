<?php

declare(strict_types=1);

use Jose\Component\Signature\Algorithm\Ed25519;
use Jose\Component\Signature\Algorithm\Ed448;
use Jose\Component\Signature\Algorithm\EdDSA;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * Each algorithm is registered only when the platform can run it: the algorithm manager factory instantiates every
 * tagged algorithm when the container is built, and an unsupported one would throw there. "Ed25519" and the
 * deprecated "EdDSA" need sodium, or OpenSSL on PHP 8.4; "Ed448" OpenSSL on PHP 8.4.
 */
return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    if (Ed25519::isSupported()) {
        $container->set(EdDSA::class)
            ->tag('jose.algorithm', [
                'alias' => 'EdDSA',
            ]);
        $container->set(Ed25519::class)
            ->tag('jose.algorithm', [
                'alias' => 'Ed25519',
            ]);
    }

    if (Ed448::isSupported()) {
        $container->set(Ed448::class)
            ->tag('jose.algorithm', [
                'alias' => 'Ed448',
            ]);
    }
};

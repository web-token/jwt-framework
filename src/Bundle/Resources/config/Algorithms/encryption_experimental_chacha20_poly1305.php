<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\KeyEncryption\Chacha20Poly1305;
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

    $container->set(Chacha20Poly1305::class)
        ->tag('jose.algorithm', [
            'alias' => 'chacha20-poly1305',
        ]);
};

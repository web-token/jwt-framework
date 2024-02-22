<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CCM_16_128;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CCM_16_64;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CCM_64_128;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CCM_64_64;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_16_128;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_16_64;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_64_128;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_64_64;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128CTR;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192CTR;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256CTR;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP384;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP512;
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

    $container->set(A128CTR::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128CTR',
        ]);

    $container->set(A192CTR::class)
        ->tag('jose.algorithm', [
            'alias' => 'A192CTR',
        ]);

    $container->set(A256CTR::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256CTR',
        ]);

    $container->set(RSAOAEP384::class)
        ->tag('jose.algorithm', [
            'alias' => 'RSA-OAEP-384',
        ]);

    $container->set(RSAOAEP512::class)
        ->tag('jose.algorithm', [
            'alias' => 'RSA-OAEP-512',
        ]);

    $container->set(A128CCM_16_64::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128CCM-16-64',
        ]);

    $container->set(A128CCM_16_128::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128CCM-16-128',
        ]);

    $container->set(A128CCM_64_64::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128CCM-64-64',
        ]);

    $container->set(A128CCM_64_128::class)
        ->tag('jose.algorithm', [
            'alias' => 'A128CCM-64-128',
        ]);

    $container->set(A256CCM_16_64::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256CCM-16-64',
        ]);

    $container->set(A256CCM_16_128::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256CCM-16-128',
        ]);

    $container->set(A256CCM_64_64::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256CCM-64-64',
        ]);

    $container->set(A256CCM_64_128::class)
        ->tag('jose.algorithm', [
            'alias' => 'A256CCM-64-128',
        ]);
};

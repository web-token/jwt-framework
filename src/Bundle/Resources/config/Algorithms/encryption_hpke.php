<?php

declare(strict_types=1);

use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE0;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE0KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE1;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE1KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE2;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE2KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE3;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE3KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE4;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE5;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE5KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE6;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE7;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE7KE;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * Each algorithm is registered only when the platform can run it: the algorithm manager factory instantiates every
 * tagged algorithm when the container is built, and an unsupported one would throw there. The X25519 suites need
 * sodium, or OpenSSL on PHP 8.4; the X448 suites OpenSSL on PHP 8.4; the ChaCha20Poly1305 suites an OpenSSL providing
 * that cipher.
 */
return function (ContainerConfigurator $container): void {
    $container = $container->services()
        ->defaults()
        ->private()
        ->autoconfigure()
        ->autowire();

    $algorithms = [
        'HPKE-0' => HPKE0::class,
        'HPKE-1' => HPKE1::class,
        'HPKE-2' => HPKE2::class,
        'HPKE-3' => HPKE3::class,
        'HPKE-4' => HPKE4::class,
        'HPKE-5' => HPKE5::class,
        'HPKE-6' => HPKE6::class,
        'HPKE-7' => HPKE7::class,
        'HPKE-0-KE' => HPKE0KE::class,
        'HPKE-1-KE' => HPKE1KE::class,
        'HPKE-2-KE' => HPKE2KE::class,
        'HPKE-3-KE' => HPKE3KE::class,
        'HPKE-5-KE' => HPKE5KE::class,
        'HPKE-7-KE' => HPKE7KE::class,
    ];
    foreach ($algorithms as $alias => $class) {
        if ($class::isSupported()) {
            $container->set($class)
                ->tag('jose.algorithm', [
                    'alias' => $alias,
                ]);
        }
    }
};

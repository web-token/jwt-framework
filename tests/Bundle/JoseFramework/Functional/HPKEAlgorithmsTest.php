<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\KeyEncryption\AbstractHPKE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\AbstractHPKEKE;
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
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function in_array;

/**
 * The HPKE algorithms of draft-ietf-jose-hpke-encrypt are registered when the platform can run them: the X448 suites
 * need OpenSSL on PHP 8.4, the X25519 ones sodium or OpenSSL on PHP 8.4, and the ChaCha20Poly1305 ones an OpenSSL
 * providing that cipher.
 *
 * @internal
 */
final class HPKEAlgorithmsTest extends WebTestCase
{
    /**
     * @return iterable<string, array{string, class-string<AbstractHPKE|AbstractHPKEKE>}>
     */
    public static function algorithms(): iterable
    {
        yield 'HPKE-0' => ['HPKE-0', HPKE0::class];
        yield 'HPKE-1' => ['HPKE-1', HPKE1::class];
        yield 'HPKE-2' => ['HPKE-2', HPKE2::class];
        yield 'HPKE-3' => ['HPKE-3', HPKE3::class];
        yield 'HPKE-4' => ['HPKE-4', HPKE4::class];
        yield 'HPKE-5' => ['HPKE-5', HPKE5::class];
        yield 'HPKE-6' => ['HPKE-6', HPKE6::class];
        yield 'HPKE-7' => ['HPKE-7', HPKE7::class];
        yield 'HPKE-0-KE' => ['HPKE-0-KE', HPKE0KE::class];
        yield 'HPKE-1-KE' => ['HPKE-1-KE', HPKE1KE::class];
        yield 'HPKE-2-KE' => ['HPKE-2-KE', HPKE2KE::class];
        yield 'HPKE-3-KE' => ['HPKE-3-KE', HPKE3KE::class];
        yield 'HPKE-5-KE' => ['HPKE-5-KE', HPKE5KE::class];
        yield 'HPKE-7-KE' => ['HPKE-7-KE', HPKE7KE::class];
    }

    /**
     * @param class-string<AbstractHPKE|AbstractHPKEKE> $class
     */
    #[Test]
    #[DataProvider('algorithms')]
    public function theAlgorithmIsRegisteredWhenSupported(string $alias, string $class): void
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();
        $factory = $container->get(AlgorithmManagerFactory::class);
        static::assertInstanceOf(AlgorithmManagerFactory::class, $factory);

        static::assertSame($class::isSupported(), in_array($alias, $factory->aliases(), true));
        if ($class::isSupported()) {
            static::assertInstanceOf($class, $factory->create([$alias])->get($alias));
        }
    }
}

<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Rsa15\KeyEncryption\RSA15;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The "RSA1_5" algorithm of the jose-rsa15 package is registered by its own configuration file. That file is only
 * loaded when the package is installed, so a stale class name would silently make the algorithm unavailable.
 *
 * @internal
 */
final class Rsa15AlgorithmTest extends WebTestCase
{
    #[Test]
    public function theRsa15AlgorithmIsRegistered(): void
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();

        /** @var AlgorithmManagerFactory $factory */
        $factory = $container->get(AlgorithmManagerFactory::class);

        static::assertContains('RSA1_5', $factory->aliases());
        static::assertSame('RSA1_5', $factory->create(['RSA1_5'])->get('RSA1_5')->name());
    }

    #[Test]
    public function theRsa15AlgorithmIsTheOneOfTheRsa15Package(): void
    {
        static::assertTrue(class_exists(RSA15::class));

        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();

        /** @var AlgorithmManagerFactory $factory */
        $factory = $container->get(AlgorithmManagerFactory::class);

        static::assertInstanceOf(RSA15::class, $factory->create(['RSA1_5'])->get('RSA1_5'));
    }
}

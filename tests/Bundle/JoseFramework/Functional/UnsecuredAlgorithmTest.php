<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use Jose\Unsecured\Signature\None;
use PHPUnit\Framework\Attributes\Test;

/**
 * The "none" algorithm of the jose-unsecured package is registered by its own configuration file. That file is only
 * loaded when the package is installed, so a stale class name would silently make the algorithm unavailable.
 *
 * @internal
 */
final class UnsecuredAlgorithmTest extends WebTestCase
{
    #[Test]
    public function theNoneAlgorithmIsRegistered(): void
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();

        /** @var AlgorithmManagerFactory $factory */
        $factory = $container->get(AlgorithmManagerFactory::class);

        static::assertContains('none', $factory->aliases());
        static::assertSame('none', $factory->create(['none'])->get('none')->name());
    }

    #[Test]
    public function theNoneAlgorithmIsTheOneOfTheUnsecuredPackage(): void
    {
        static::assertTrue(class_exists(None::class));

        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();

        /** @var AlgorithmManagerFactory $factory */
        $factory = $container->get(AlgorithmManagerFactory::class);

        static::assertInstanceOf(None::class, $factory->create(['none'])->get('none'));
    }
}

<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Algorithm\None as LibraryNone;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Service\DeprecatedNoneConsumer;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use Jose\Unsecured\Signature\None;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

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

    /**
     * Until 4.2, the bundle registered the algorithm under the id of the library class, which an application could
     * reference or autowire. That class moved to the jose-unsecured package in 4.3: the "none" alias is served by the
     * class of the package, and the library class survives as a deprecated service until 5.0.0: using it triggers
     * the deprecation of the service, then that of the class.
     */
    #[Test]
    public function theLibraryClassIsStillADeprecatedService(): void
    {
        static::ensureKernelShutdown();
        $container = static::createClient()
            ->getContainer();

        /** @var AlgorithmManagerFactory $factory */
        $factory = $container->get(AlgorithmManagerFactory::class);
        static::assertSame(None::class, $factory->create(['none'])->get('none')::class);

        $consumer = null;
        $deprecations = $this->collectDeprecations(static function () use ($container, &$consumer): void {
            $consumer = $container->get(DeprecatedNoneConsumer::class);
        });

        static::assertInstanceOf(DeprecatedNoneConsumer::class, $consumer);
        static::assertSame(LibraryNone::class, $consumer->algorithm::class);
        static::assertSame('none', $consumer->algorithm->name());
        static::assertCount(2, $deprecations);
        static::assertSame(
            'Since web-token/jwt-framework 4.3.0: The "' . LibraryNone::class . '" service is deprecated and will be removed in 5.0.0: the "none" algorithm is now shipped by the "web-token/jwt-unsecured" package and registered as "' . None::class . '", under the same "none" alias.',
            $deprecations[0]
        );
        static::assertStringStartsWith(
            'Since web-token/jwt-framework 4.3.0: The class "' . LibraryNone::class . '" is deprecated',
            $deprecations[1]
        );
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}

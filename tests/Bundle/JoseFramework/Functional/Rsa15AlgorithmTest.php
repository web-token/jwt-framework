<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15 as LibraryRSA15;
use Jose\Rsa15\KeyEncryption\RSA15;
use Jose\Tests\Bundle\JoseFramework\TestBundle\Service\DeprecatedRSA15Consumer;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

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

    /**
     * Until 4.2, the bundle registered the algorithm under the id of the library class, which an application could
     * reference or autowire. That class moved to the jose-rsa15 package in 4.3: the "RSA1_5" alias is served by the
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
        static::assertSame(RSA15::class, $factory->create(['RSA1_5'])->get('RSA1_5')::class);

        $consumer = null;
        $deprecations = $this->collectDeprecations(static function () use ($container, &$consumer): void {
            $consumer = $container->get(DeprecatedRSA15Consumer::class);
        });

        static::assertInstanceOf(DeprecatedRSA15Consumer::class, $consumer);
        static::assertSame(LibraryRSA15::class, $consumer->algorithm::class);
        static::assertSame('RSA1_5', $consumer->algorithm->name());
        static::assertCount(2, $deprecations);
        static::assertSame(
            'Since web-token/jwt-framework 4.3.0: The "' . LibraryRSA15::class . '" service is deprecated and will be removed in 5.0.0: the "RSA1_5" algorithm is now shipped by the "web-token/jwt-rsa15" package and registered as "' . RSA15::class . '", under the same "RSA1_5" alias.',
            $deprecations[0]
        );
        static::assertStringStartsWith(
            'Since web-token/jwt-framework 4.3.0: The class "' . LibraryRSA15::class . '" is deprecated',
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

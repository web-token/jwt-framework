<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory;
use Jose\Bundle\JoseFramework\Services\JWEDecrypterFactory;
use Jose\Bundle\JoseFramework\Services\JWELoaderFactory;
use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory;
use Jose\Bundle\JoseFramework\Services\JWSVerifierFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\EventDispatcher\EventDispatcher;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use const E_USER_DEPRECATED;

/**
 * @internal
 */
final class LoaderFactoriesWithoutHeaderCheckerManagerFactoryTest extends WebTestCase
{
    private const MESSAGE = 'Since web-token/jwt-framework 4.3.0: Creating a "%s" without a header checker manager factory is deprecated and will not be possible in 5.0.0: the loaders it creates check no header parameter, not even those listed in "crit". Pass a "%s" that has the "%s" token type support.';

    #[Test]
    public function theLoaderFactoriesWithoutHeaderCheckerManagerFactoryAreDeprecated(): void
    {
        $eventDispatcher = new EventDispatcher();
        $algorithmManagerFactory = new AlgorithmManagerFactory([]);
        $jweSerializerManagerFactory = new JWESerializerManagerFactory();
        $jweDecrypterFactory = new JWEDecrypterFactory($algorithmManagerFactory, $eventDispatcher);
        $jwsSerializerManagerFactory = new JWSSerializerManagerFactory();
        $jwsVerifierFactory = new JWSVerifierFactory($algorithmManagerFactory, $eventDispatcher);

        $deprecations = $this->collectDeprecations(static function () use (
            $eventDispatcher,
            $jweSerializerManagerFactory,
            $jweDecrypterFactory,
            $jwsSerializerManagerFactory,
            $jwsVerifierFactory
        ): void {
            new JWELoaderFactory($jweSerializerManagerFactory, $jweDecrypterFactory, null, $eventDispatcher);
            new JWSLoaderFactory($jwsSerializerManagerFactory, $jwsVerifierFactory, null, $eventDispatcher);
        });

        static::assertSame([
            sprintf(self::MESSAGE, JWELoaderFactory::class, HeaderCheckerManagerFactory::class, JWETokenSupport::class),
            sprintf(self::MESSAGE, JWSLoaderFactory::class, HeaderCheckerManagerFactory::class, JWSTokenSupport::class),
        ], $deprecations);
    }

    #[Test]
    public function theLoaderFactoriesOfTheContainerAreNotDeprecated(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        $deprecations = $this->collectDeprecations(static function () use ($container): void {
            $container->get(JWELoaderFactory::class);
            $container->get(JWSLoaderFactory::class);
        });

        static::assertSame([], $deprecations);
    }

    /**
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

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

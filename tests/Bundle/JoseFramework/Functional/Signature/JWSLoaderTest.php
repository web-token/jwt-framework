<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use InvalidArgumentException;
use Jose\Bundle\JoseFramework\Services\JWSLoaderFactory as JWSLoaderFactoryService;
use Jose\Bundle\JoseFramework\Services\JWSVerifierFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * @internal
 */
final class JWSLoaderTest extends WebTestCase
{
    #[Test]
    public static function theJWSLoaderFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(JWSLoaderFactoryService::class));
    }

    #[Test]
    public static function theWELoaderFactoryCanCreateAJWSLoader(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        /** @var JWSLoaderFactory $jwsLoaderFactory */
        $jwsLoaderFactory = $container->get(JWSLoaderFactoryService::class);

        $jws = $jwsLoaderFactory->create(['jws_compact'], ['RS512']);

        static::assertSame(['jws_compact'], $jws->getSerializerManager()->list());
        static::assertSame(['RS512'], $jws->getJwsVerifier()->getSignatureAlgorithmManager()->list());
    }

    #[Test]
    public static function aJWSLoaderCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_loader.jws_loader1'));

        $jws = $container->get('jose.jws_loader.jws_loader1');
        static::assertInstanceOf(JWSLoader::class, $jws);
    }

    #[Test]
    public static function aJWSLoaderCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.jws_loader.jws_loader2'));

        $jws = $container->get('jose.jws_loader.jws_loader2');
        static::assertInstanceOf(JWSLoader::class, $jws);
    }

    #[Test]
    public function theJWSLoaderFactoryRefusesHeaderCheckersWithoutAHeaderCheckerManagerFactory(): void
    {
        $eventDispatcher = new EventDispatcher();
        $serializerManagerFactory = new JWSSerializerManagerFactory();
        $serializerManagerFactory->add(new CompactSerializer());
        $jwsLoaderFactory = new JWSLoaderFactoryService(
            $serializerManagerFactory,
            new JWSVerifierFactory(new AlgorithmManagerFactory([new HS256()]), $eventDispatcher),
            null,
            $eventDispatcher
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Header checkers were requested, but no header checker manager factory is available.'
        );

        $jwsLoaderFactory->create(['jws_compact'], ['HS256'], ['custom_checker']);
    }

    #[Test]
    public function theLibraryJWSLoaderFactoryRegisteredWithAutowiringRefusesHeaderCheckers(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $jwsLoaderFactory = $client->getContainer()
            ->get(JWSLoaderFactory::class);
        static::assertInstanceOf(JWSLoaderFactory::class, $jwsLoaderFactory);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Header checkers were requested, but no header checker manager factory is available.'
        );

        $jwsLoaderFactory->create(['jws_compact'], ['HS256'], ['custom_checker']);
    }
}

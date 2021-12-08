<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class JWSSerializerTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(JWSBuilderFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
    }

    /**
     * @test
     */
    public function jWSSerializerManagerFromConfigurationIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jws_serializer.jws_serializer1'));

        $jws = $container->get('jose.jws_serializer.jws_serializer1');
        static::assertInstanceOf(JWSSerializerManager::class, $jws);
    }

    /**
     * @test
     */
    public function jWSSerializerManagerFromExternalBundleExtensionIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.jws_serializer.jws_serializer2'));

        $jws = $container->get('jose.jws_serializer.jws_serializer2');
        static::assertInstanceOf(JWSSerializerManager::class, $jws);
    }
}

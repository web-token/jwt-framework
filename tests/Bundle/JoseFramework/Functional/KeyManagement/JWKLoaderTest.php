<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class JWKLoaderTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(JWKFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-key-mgmt" is not installed.');
        }
    }

    /**
     * @test
     */
    public function aJWKCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.jwk1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwk1'));
    }

    /**
     * @test
     */
    public function aJWKCanBeDefinedFromAnotherBundle(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.jwk2'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwk2'));
    }

    /**
     * @test
     */
    public function aX509InFileCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.certificate1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.certificate1'));
    }

    /**
     * @test
     */
    public function aDirectX509InputCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.x5c1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.x5c1'));
    }

    /**
     * @test
     */
    public function anEncryptedKeyFileCanBeLoadedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.file1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.file1'));
    }

    /**
     * @test
     */
    public function aJWKCanBeLoadedFromAJwkSetInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.jwkset1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwkset1'));
    }

    /**
     * @test
     */
    public function aJWKCanBeLoadedFromASecretInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertInstanceOf(ContainerInterface::class, $container);
        static::assertTrue($container->has('jose.key.secret1'));
        $jwk = $container->get('jose.key.secret1');

        static::assertInstanceOf(JWK::class, $jwk);
        static::assertSame('oct', $jwk->get('kty'));
        static::assertSame('enc', $jwk->get('use'));
        static::assertSame('RS512', $jwk->get('alg'));
        static::assertSame('This is my secret', Base64UrlSafe::decode($jwk->get('k')));
    }
}

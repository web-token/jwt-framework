<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @internal
 */
final class JWKLoaderTest extends WebTestCase
{
    #[Test]
    public static function aJWKCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has('jose.key.jwk1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwk1'));
    }

    #[Test]
    public static function aJWKCanBeDefinedFromAnotherBundle(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has('jose.key.jwk2'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwk2'));
    }

    #[Test]
    public static function aX509InFileCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has('jose.key.certificate1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.certificate1'));
    }

    #[Test]
    public static function aDirectX509InputCanBeDefinedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has('jose.key.x5c1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.x5c1'));
    }

    #[Test]
    public static function anEncryptedKeyFileCanBeLoadedInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has('jose.key.file1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.file1'));
    }

    #[Test]
    public static function aJWKCanBeLoadedFromAJwkSetInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has('jose.key.jwkset1'));
        static::assertInstanceOf(JWK::class, $container->get('jose.key.jwkset1'));
    }

    #[Test]
    public static function aJWKCanBeLoadedFromASecretInTheConfiguration(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();

        $container = $client->getContainer();
        static::assertTrue($container->has('jose.key.secret1'));
        $jwk = $container->get('jose.key.secret1');

        static::assertInstanceOf(JWK::class, $jwk);
        static::assertSame('oct', $jwk->get('kty'));
        static::assertSame('enc', $jwk->get('use'));
        static::assertSame('RS512', $jwk->get('alg'));
        static::assertSame('This is my secret', Base64UrlSafe::decode($jwk->get('k')));
    }
}

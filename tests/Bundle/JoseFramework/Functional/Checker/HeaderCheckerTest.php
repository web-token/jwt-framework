<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Checker;

use Jose\Bundle\JoseFramework\Services\HeaderCheckerManager;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory as HeaderCheckerManagerFactoryService;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\TypeChecker;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * @internal
 */
final class HeaderCheckerTest extends WebTestCase
{
    #[Test]
    public static function theHeaderCheckerManagerFactoryIsAvailable(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has(HeaderCheckerManagerFactoryService::class));
    }

    #[Test]
    public static function theHeaderCheckerManagerFactoryCanCreateAHeaderCheckerManager(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        $headerCheckerManagerFactory = $container->get(HeaderCheckerManagerFactoryService::class);
        static::assertInstanceOf(HeaderCheckerManagerFactoryService::class, $headerCheckerManagerFactory);

        $aliases = $headerCheckerManagerFactory->aliases();
        $headerCheckerManagerFactory->create($aliases);
    }

    #[Test]
    public static function aHeaderCheckerCanBeDefinedUsingTheConfigurationFile(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.header_checker.checker1'));
    }

    #[Test]
    public static function aHeaderCheckerCanBeDefinedFromAnotherBundleUsingTheHelper(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        static::assertTrue($container->has('jose.header_checker.checker2'));
    }

    #[Test]
    #[DataProvider('managersWithATypeChecker')]
    public static function aTypeCheckerIsRegisteredAndWiredWhenAcceptedTypesAreConfigured(string $name): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();

        $headerCheckerManagerFactory = $container->get(HeaderCheckerManagerFactoryService::class);
        static::assertInstanceOf(HeaderCheckerManagerFactoryService::class, $headerCheckerManagerFactory);
        static::assertContains('typ.' . $name, $headerCheckerManagerFactory->aliases());

        $headerCheckerManager = $container->get('jose.header_checker.' . $name);
        static::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);
        static::assertInstanceOf(TypeChecker::class, $headerCheckerManager->getCheckers()['typ'] ?? null);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function managersWithATypeChecker(): iterable
    {
        yield 'from the configuration file' => ['access_token'];
        yield 'from another bundle using the helper' => ['access_token2'];
    }

    #[Test]
    public static function theConfiguredTypeCheckerAcceptsTheConfiguredTypes(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        $headerCheckerManager = $container->get('jose.header_checker.access_token');

        $headerCheckerManager->check(self::jwsWithType($container, 'AT+JWT'), 0, ['typ']);
        $headerCheckerManager->check(self::jwsWithType($container, 'dpop+jwt'), 0, ['typ']);
    }

    #[Test]
    public function theConfiguredTypeCheckerRejectsAnyOtherType(): void
    {
        static::ensureKernelShutdown();
        $client = static::createClient();
        $container = $client->getContainer();
        $headerCheckerManager = $container->get('jose.header_checker.access_token');

        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('Unsupported type.');
        $headerCheckerManager->check(self::jwsWithType($container, 'JWT'), 0, ['typ']);
    }

    private static function jwsWithType(ContainerInterface $container, string $type): JWS
    {
        $jwsBuilder = $container->get('jose.jws_builder.builder1');
        static::assertInstanceOf(JWSBuilder::class, $jwsBuilder);
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        return $jwsBuilder
            ->withPayload('{}')
            ->addSignature($key, [
                'alg' => 'HS256',
                'typ' => $type,
            ])
            ->build();
    }
}

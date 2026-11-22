<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Component\Core\Exception\JsonBoundExceededException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\X5UFactory;
use Jose\Tests\Bundle\JoseFramework\IsolatedKernel;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Throwable;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function str_repeat;
use const E_USER_DEPRECATED;

/**
 * The "jose.jku_factory.allow_large_key_sets" option sets how the factories load a key set of more than 4096 JSON
 * values: true loads it, false refuses it. When it is not set, the key set is loaded with a deprecation.
 *
 * @internal
 */
final class JKUFactoryLargeKeySetsTest extends TestCase
{
    private const URL = 'https://keys.example.com/keys';

    private const DEPRECATION = 'Since web-token/jwt-framework 4.3.0: Loading a key set of more than 4096 JSON values is deprecated and "%s" will refuse it by default in 5.0.0. Pass true as the third argument of the constructor to keep loading it, or false to refuse it now. With the bundle, set the "jose.jku_factory.allow_large_key_sets" option.';

    private ?IsolatedKernel $kernel = null;

    protected function tearDown(): void
    {
        if ($this->kernel !== null) {
            $this->kernel->shutdown();
            (new Filesystem())->remove($this->kernel->getVarDir());
            $this->kernel = null;
        }

        parent::tearDown();
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function theFactoriesRefuseLargeKeySetsWhenTheOptionIsFalse(string $factory): void
    {
        $service = $this->getFactory($factory, self::largeDocument($factory), [
            'allow_large_key_sets' => false,
        ]);

        $this->expectException(JsonBoundExceededException::class);

        $service->loadFromUrl(self::URL);
    }

    #[Test]
    public function theFactoriesLoadLargeKeySetsSilentlyWhenTheOptionIsTrue(): void
    {
        $service = $this->getFactory(JKUFactory::class, self::largeDocument(JKUFactory::class), [
            'allow_large_key_sets' => true,
        ]);

        $keySet = null;
        $deprecations = $this->collectDeprecations(static function () use ($service, &$keySet): void {
            $keySet = $service->loadFromUrl(self::URL);
        });

        static::assertSame([], $deprecations);
        static::assertInstanceOf(JWKSet::class, $keySet);
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function theFactoriesLoadLargeKeySetsWithADeprecationWhenTheOptionIsNotSet(string $factory): void
    {
        $service = $this->getFactory($factory, self::largeDocument($factory), []);

        $deprecations = $this->collectDeprecations(static function () use ($service): void {
            try {
                $service->loadFromUrl(self::URL);
            } catch (Throwable) {
            }
        });

        static::assertSame([sprintf(self::DEPRECATION, $factory)], $deprecations);
    }

    /**
     * The redirect policy stays the second argument of the factories when only the large key sets option is set.
     */
    #[Test]
    public function theRedirectPolicyKeepsItsPlaceBesideTheLargeKeySetsOption(): void
    {
        $service = $this->getFactory(JKUFactory::class, '{"keys":[]}', [
            'follow_redirects' => false,
            'allow_large_key_sets' => true,
        ], true);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to get the key set: redirects are refused.');

        $service->loadFromUrl(self::URL);
    }

    /**
     * @return iterable<string, array{class-string<JKUFactory|X5UFactory>}>
     */
    public static function factories(): iterable
    {
        yield 'JKU' => [JKUFactory::class];
        yield 'X5U' => [X5UFactory::class];
    }

    /**
     * A document of 4097 values: a key set for JKUFactory, and an object of certificates for X5UFactory, whose array
     * of values is not a certificate.
     *
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    private static function largeDocument(string $factory): string
    {
        return $factory === JKUFactory::class
            ? '{"keys":[{"kty":"oct","k":"AAAA","x":[' . str_repeat('0,', 4091) . '0]}]}'
            : '{"key":[' . str_repeat('0,', 4095) . '0]}';
    }

    /**
     * Boots a kernel whose key set client answers every request with the given document, and returns the factory
     * service.
     *
     * @template T of JKUFactory|X5UFactory
     *
     * @param class-string<T> $factory
     * @param array<string, bool> $options
     *
     * @return T
     */
    private function getFactory(
        string $factory,
        string $document,
        array $options,
        bool $redirected = false
    ): JKUFactory|X5UFactory {
        $this->kernel = new IsolatedKernel(static function (ContainerBuilder $container) use (
            $document,
            $options,
            $redirected
        ): void {
            $container->register('app.key_set_client', MockHttpClient::class)
                ->setArguments([
                    new Definition(MockResponse::class, [
                        $document,
                        $redirected ? [
                            'redirect_count' => 1,
                            'url' => 'http://127.0.0.1:8080/keys',
                        ] : [],
                    ]),
                ]);
            $container->loadFromExtension('jose', [
                'jku_factory' => [
                    'enabled' => true,
                    'client' => 'app.key_set_client',
                ] + $options,
            ]);
        });
        $this->kernel->boot();

        $service = $this->kernel->getContainer()
            ->get($factory);
        static::assertInstanceOf($factory, $service);

        return $service;
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

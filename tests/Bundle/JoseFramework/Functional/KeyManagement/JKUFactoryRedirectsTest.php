<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Component\Core\Exception\RuntimeException;
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
use function file_get_contents;
use function json_encode;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use const E_USER_DEPRECATED;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class JKUFactoryRedirectsTest extends TestCase
{
    private const URL = 'https://keys.example.com/keys';

    private const DEPRECATION = 'Since web-token/jwt-framework 4.3.0: Fetching a key set through a redirect is deprecated and "%s" will refuse redirects by default in 5.0.0. Use the URL the redirect leads to, or pass true as the second argument of the constructor to keep following redirects, or false to refuse them. With the bundle, set the "jose.jku_factory.follow_redirects" option.';

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
    public function theFactoriesRefuseRedirectsWhenTheOptionIsFalse(string $factory, string $document): void
    {
        $service = $this->getFactory($factory, $document, [
            'follow_redirects' => false,
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to get the key set: redirects are refused.');

        $service->loadFromUrl(self::URL);
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function theFactoriesFollowRedirectsSilentlyWhenTheOptionIsTrue(string $factory, string $document): void
    {
        $service = $this->getFactory($factory, $document, [
            'follow_redirects' => true,
        ]);

        $deprecations = $this->collectDeprecations(static function () use ($service): void {
            static::assertCount(1, $service->loadFromUrl(self::URL));
        });

        static::assertSame([], $deprecations);
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function theFactoriesFollowRedirectsWithADeprecationWhenTheOptionIsNotSet(
        string $factory,
        string $document
    ): void {
        $service = $this->getFactory($factory, $document, []);

        $deprecations = $this->collectDeprecations(static function () use ($service): void {
            static::assertCount(1, $service->loadFromUrl(self::URL));
        });

        static::assertSame([sprintf(self::DEPRECATION, $factory)], $deprecations);
    }

    /**
     * @return iterable<string, array{class-string<JKUFactory|X5UFactory>, string}>
     */
    public static function factories(): iterable
    {
        yield 'JKU' => [JKUFactory::class, '{"keys":[{"kty":"oct","kid":"target","k":"dGFyZ2V0"}]}'];
        yield 'X5U' => [X5UFactory::class, json_encode([
            'target' => file_get_contents(__DIR__ . '/../../../../Component/KeyManagement/RSA/PEM/2048b-rsa-example-cert.pem'),
        ], JSON_THROW_ON_ERROR)];
    }

    /**
     * Boots a kernel whose key set client answers every request with the given document, as if it had followed a
     * redirect, and returns the factory service.
     *
     * @template T of JKUFactory|X5UFactory
     *
     * @param class-string<T> $factory
     * @param array<string, bool> $options
     *
     * @return T
     */
    private function getFactory(string $factory, string $document, array $options): JKUFactory|X5UFactory
    {
        $this->kernel = new IsolatedKernel(static function (ContainerBuilder $container) use (
            $document,
            $options
        ): void {
            $container->register('app.key_set_client', MockHttpClient::class)
                ->setArguments([
                    new Definition(MockResponse::class, [
                        $document,
                        [
                            'redirect_count' => 1,
                            'url' => 'http://127.0.0.1:8080/keys',
                        ],
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

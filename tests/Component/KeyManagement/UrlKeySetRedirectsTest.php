<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\UrlKeySetFactory;
use Jose\Component\KeyManagement\X5UFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use function array_keys;
use function file_get_contents;
use function hash;
use function json_encode;
use function restore_error_handler;
use function serialize;
use function set_error_handler;
use function sprintf;
use const E_USER_DEPRECATED;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class UrlKeySetRedirectsTest extends TestCase
{
    private const URL = 'https://keys.example.com/jwks';

    private const TARGET = 'http://127.0.0.1:8080/admin/cache/purge?all=1';

    private const KEY_SET = '{"keys":[{"kty":"oct","kid":"target","k":"dGFyZ2V0"}]}';

    private const DEPRECATION = 'Since web-token/jwt-framework 4.3.0: Fetching a key set through a redirect is deprecated and "%s" will refuse redirects by default in 5.0.0. Use the URL the redirect leads to, or pass true as the second argument of the constructor to keep following redirects, or false to refuse them. With the bundle, set the "jose.jku_factory.follow_redirects" option.';

    private const REFUSED = 'Unable to get the key set: redirects are refused.';

    /**
     * @var list<string>
     */
    private array $requestedUrls = [];

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function aRedirectIsNotFollowedWhenRedirectsAreRefused(string $factory, string $document): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(self::REFUSED);
        $this->expectExceptionCode(302);

        try {
            (new $factory($this->getRedirectingHttpClient($document), false))->loadFromUrl(self::URL);
        } finally {
            static::assertSame([self::URL], $this->requestedUrls);
        }
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function aKeySetFetchedThroughARedirectIsRejectedWhenRedirectsAreRefused(
        string $factory,
        string $document
    ): void {
        $client = new MockHttpClient(new MockResponse($document, [
            'redirect_count' => 1,
            'url' => self::TARGET,
        ]));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(self::REFUSED);

        (new $factory($client, false))->loadFromUrl(self::URL);
    }

    #[Test]
    #[DataProvider('redirectStatusCodes')]
    public function aRedirectAnswerIsRejectedWhenRedirectsAreRefused(int $statusCode): void
    {
        $client = new MockHttpClient(new MockResponse('', [
            'http_code' => $statusCode,
            'response_headers' => ['Location: ' . self::TARGET],
        ]));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(self::REFUSED);
        $this->expectExceptionCode($statusCode);

        (new JKUFactory($client, false))->loadFromUrl(self::URL);
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function aKeySetServedWithoutRedirectIsLoadedWhenRedirectsAreRefused(
        string $factory,
        string $document
    ): void {
        $maxRedirects = null;
        $client = new MockHttpClient(static function (string $method, string $url, array $options) use (
            $document,
            &$maxRedirects
        ): MockResponse {
            $maxRedirects = $options['max_redirects'] ?? null;

            return new MockResponse($document);
        });

        $keySet = (new $factory($client, false))->loadFromUrl(self::URL);

        static::assertSame(['target'], array_keys($keySet->all()));
        static::assertSame(0, $maxRedirects);
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     * @param list<null> $policy
     */
    #[Test]
    #[DataProvider('factoriesWithoutPolicy')]
    public function followingARedirectIsDeprecatedWhenNoPolicyIsSet(
        string $factory,
        string $document,
        array $policy
    ): void {
        $instance = new $factory($this->getRedirectingHttpClient($document), ...$policy);

        $keySet = null;
        $deprecations = $this->collectDeprecations(static function () use ($instance, &$keySet): void {
            $keySet = $instance->loadFromUrl(self::URL);
        });

        static::assertSame([sprintf(self::DEPRECATION, $factory)], $deprecations);
        static::assertInstanceOf(JWKSet::class, $keySet);
        static::assertSame(['target'], array_keys($keySet->all()));
        static::assertSame([self::URL, self::TARGET], $this->requestedUrls);
    }

    /**
     * @param class-string<JKUFactory|X5UFactory> $factory
     */
    #[Test]
    #[DataProvider('factories')]
    public function aRedirectIsFollowedWithoutDeprecationWhenRedirectsAreFollowed(
        string $factory,
        string $document
    ): void {
        $instance = new $factory($this->getRedirectingHttpClient($document), true);

        $keySet = null;
        $deprecations = $this->collectDeprecations(static function () use ($instance, &$keySet): void {
            $keySet = $instance->loadFromUrl(self::URL);
        });

        static::assertSame([], $deprecations);
        static::assertInstanceOf(JWKSet::class, $keySet);
        static::assertSame(['target'], array_keys($keySet->all()));
        static::assertSame([self::URL, self::TARGET], $this->requestedUrls);
    }

    /**
     * @param list<bool|null> $policy
     */
    #[Test]
    #[DataProvider('policiesThatFollowRedirects')]
    public function theRedirectSettingsOfTheClientAreKeptUnlessRedirectsAreRefused(array $policy): void
    {
        $maxRedirects = null;
        $client = (new MockHttpClient(static function (string $method, string $url, array $options) use (
            &$maxRedirects
        ): MockResponse {
            $maxRedirects = $options['max_redirects'] ?? null;

            return new MockResponse(self::KEY_SET);
        }))->withOptions([
            'max_redirects' => 3,
        ]);

        (new JKUFactory($client, ...$policy))->loadFromUrl(self::URL);

        static::assertSame(3, $maxRedirects);
    }

    #[Test]
    public function aRedirectTheClientDoesNotFollowFailsAsBeforeWhenNoPolicyIsSet(): void
    {
        $client = new MockHttpClient(new MockResponse('', [
            'http_code' => 302,
            'response_headers' => ['Location: ' . self::TARGET],
        ]));

        $this->expectException(RedirectionExceptionInterface::class);

        (new JKUFactory($client))->loadFromUrl(self::URL);
    }

    #[Test]
    #[DataProvider('invalidPolicies')]
    public function theRedirectPolicyMustBeABoolean(mixed $policy): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The redirect policy must be a boolean: true follows redirects, false refuses them.'
        );

        new X5UFactory(new MockHttpClient(), $policy);
    }

    #[Test]
    public function aFactoryThatRefusesRedirectsIgnoresTheCacheEntriesOfOneThatFollowsThem(): void
    {
        $pool = new ArrayAdapter();
        $following = new JKUFactory($this->getRedirectingHttpClient(self::KEY_SET), true);
        $refusing = new JKUFactory($this->getRedirectingHttpClient(self::KEY_SET), false);
        $this->collectDeprecations(static function () use ($following, $refusing, $pool): void {
            $following->enabledCache($pool);
            $refusing->enabledCache($pool);
        });
        $following->loadFromUrl(self::URL);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(self::REFUSED);

        $refusing->loadFromUrl(self::URL);
    }

    #[Test]
    public function aFactoryThatDoesNotRefuseRedirectsKeepsTheCacheEntriesItHad(): void
    {
        $pool = new ArrayAdapter();
        $item = $pool->getItem(hash('sha256', serialize([self::URL, []])));
        $item->set(self::KEY_SET);
        $pool->save($item);
        $factory = new JKUFactory(new MockHttpClient(new MockResponse('Not found', [
            'http_code' => 404,
        ])));
        $this->collectDeprecations(static function () use ($factory, $pool): void {
            $factory->enabledCache($pool);
        });

        static::assertSame(['target'], array_keys($factory->loadFromUrl(self::URL)->all()));
    }

    #[Test]
    public function aClassExtendingTheDeprecatedBaseClassFollowsRedirectsAsBefore(): void
    {
        $client = $this->getRedirectingHttpClient(self::KEY_SET);

        $content = null;
        $deprecations = $this->collectDeprecations(static function () use ($client, &$content): void {
            $factory = new class($client) extends UrlKeySetFactory {
                public function fetch(string $url): string
                {
                    return $this->getContent($url);
                }
            };
            $content = $factory->fetch(self::URL);
        });

        static::assertSame(self::KEY_SET, $content);
        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'The class "Jose\Component\KeyManagement\UrlKeySetFactory" is deprecated',
            $deprecations[0]
        );
    }

    /**
     * @return iterable<string, array{class-string<JKUFactory|X5UFactory>, string}>
     */
    public static function factories(): iterable
    {
        yield 'JKU' => [JKUFactory::class, self::KEY_SET];
        yield 'X5U' => [X5UFactory::class, self::getCertificateSet()];
    }

    /**
     * @return iterable<string, array{class-string<JKUFactory|X5UFactory>, string, list<null>}>
     */
    public static function factoriesWithoutPolicy(): iterable
    {
        yield 'JKU without second argument' => [JKUFactory::class, self::KEY_SET, []];
        yield 'JKU with null' => [JKUFactory::class, self::KEY_SET, [null]];
        yield 'X5U without second argument' => [X5UFactory::class, self::getCertificateSet(), []];
        yield 'X5U with null' => [X5UFactory::class, self::getCertificateSet(), [null]];
    }

    /**
     * @return iterable<string, array{list<bool|null>}>
     */
    public static function policiesThatFollowRedirects(): iterable
    {
        yield 'without second argument' => [[]];
        yield 'null' => [[null]];
        yield 'true' => [[true]];
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function redirectStatusCodes(): iterable
    {
        yield 'Multiple Choices' => [300];
        yield 'Moved Permanently' => [301];
        yield 'See Other' => [303];
        yield 'Temporary Redirect' => [307];
        yield 'Permanent Redirect' => [308];
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function invalidPolicies(): iterable
    {
        yield 'string' => ['false'];
        yield 'integer' => [0];
        yield 'array' => [[]];
    }

    private static function getCertificateSet(): string
    {
        return json_encode([
            'target' => file_get_contents(__DIR__ . '/RSA/PEM/2048b-rsa-example-cert.pem'),
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Answers the key set URL with a redirect to TARGET, and follows it as the clients of Symfony do, unless the
     * request sets "max_redirects" to 0. Every URL it is asked for, the redirect target included, is recorded.
     */
    private function getRedirectingHttpClient(string $document): MockHttpClient
    {
        return new MockHttpClient(function (string $method, string $url, array $options) use (
            $document
        ): MockResponse {
            $this->requestedUrls[] = $url;
            if (($options['max_redirects'] ?? 20) <= 0) {
                return new MockResponse('', [
                    'http_code' => 302,
                    'response_headers' => ['Location: ' . self::TARGET],
                ]);
            }
            $this->requestedUrls[] = self::TARGET;

            return new MockResponse($document, [
                'redirect_count' => 1,
                'url' => self::TARGET,
            ]);
        });
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

<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\RuntimeException;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;
use function func_get_arg;
use function func_num_args;
use function hash;
use function is_bool;
use function is_int;
use function is_string;
use function serialize;
use function trigger_deprecation;

/**
 * Fetches a key set from a URL the application trusts, such as one written in its configuration. The "jku" and "x5u"
 * header parameters of a token are chosen by its sender: a URL read from them must be in an exact list of trusted
 * URLs, and be fetched with redirects refused.
 *
 * This is the shared implementation of JKUFactory and X5UFactory. They still extend UrlKeySetFactory, which uses this
 * trait too, but use it themselves: they never run the deprecated constructor of that class, and keep the same code
 * when that class is removed in 5.0.0. It is an implementation detail of those classes: it is not covered by the
 * backward compatibility promise and must not be used outside of this package.
 *
 * @internal
 *
 * @see \Jose\Tests\Component\KeyManagement\UrlKeySetFactoryTest
 * @see \Jose\Tests\Component\KeyManagement\UrlKeySetRedirectsTest
 */
trait UrlKeySetFactoryTrait
{
    private readonly HttpClientInterface $client;

    private ?CacheItemPoolInterface $cacheItemPool = null;

    private int $expiresAfter = 3600;

    private readonly ?bool $followRedirects;

    /**
     * A second argument sets how the redirects of the key set URL are handled: true follows them as the HTTP client
     * does, false refuses them and the redirected request is never sent. Without it, or with null, they are followed,
     * but a key set fetched through a redirect triggers a deprecation, as 5.0.0 refuses redirects by default. That
     * argument is not part of the signature until 5.0.0 and is read with func_num_args()/func_get_arg(1).
     */
    public function __construct(HttpClientInterface $client)
    {
        $this->client = $client;
        $followRedirects = func_num_args() > 1 ? func_get_arg(1) : null;
        if ($followRedirects !== null && ! is_bool($followRedirects)) {
            throw new InvalidArgumentException(
                'The redirect policy must be a boolean: true follows redirects, false refuses them.'
            );
        }
        $this->followRedirects = $followRedirects;
    }

    /**
     * Stores the responses in the given pool instead of fetching the URL on every call.
     *
     * @deprecated since 4.1.0 and will be removed in 5.0.0. Give the constructor an HTTP client that caches the
     *             responses instead: Symfony's CachingHttpClient wraps any client and honours the cache directives
     *             of the "jku"/"x5u" endpoint, which the fixed lifetime used here ignores.
     */
    public function enabledCache(CacheItemPoolInterface $cacheItemPool, int $expiresAfter = 3600): void
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.1.0',
            'The method "%s::enabledCache()" is deprecated and will be removed in 5.0.0. Give the constructor an HTTP client that caches the responses instead, such as "Symfony\Component\HttpClient\CachingHttpClient".',
            self::class
        );

        $this->cacheItemPool = $cacheItemPool;
        $this->expiresAfter = $expiresAfter;
    }

    /**
     * A request whose headers cannot be serialized, such as an anonymous Stringable class, bypasses the cache. A
     * factory that refuses redirects does not read the entries of one that follows them, even in a shared pool.
     *
     * @param array<string, string|string[]> $header
     */
    protected function getContent(string $url, array $header = []): string
    {
        if ($this->cacheItemPool === null) {
            return $this->sendRequest($url, $header);
        }

        $cacheKeyParts = [$url, $header];
        if ($this->followRedirects === false) {
            $cacheKeyParts[] = $this->followRedirects;
        }
        try {
            $cacheKey = hash('sha256', serialize($cacheKeyParts));
        } catch (Throwable) {
            return $this->sendRequest($url, $header);
        }

        $item = $this->cacheItemPool->getItem($cacheKey);
        $cached = $item->get();
        if ($item->isHit() && is_string($cached)) {
            return $cached;
        }

        $content = $this->sendRequest($url, $header);
        $item->expiresAfter($this->expiresAfter);
        $item->set($content);
        $this->cacheItemPool->save($item);

        return $content;
    }

    /**
     * When redirects are refused, a response that the client reached through a redirect anyway is rejected as well.
     *
     * @param array<string, string|string[]> $header
     */
    private function sendRequest(string $url, array $header): string
    {
        $options = [
            'headers' => $header,
        ];
        if ($this->followRedirects === false) {
            $options['max_redirects'] = 0;
        }
        $response = $this->client->request('GET', $url, $options);

        if ($response->getStatusCode() >= 400) {
            throw new RuntimeException('Unable to get the key set.', $response->getStatusCode());
        }

        $redirectCount = $response->getInfo('redirect_count');
        $redirected = is_int($redirectCount) && $redirectCount > 0;
        if ($this->followRedirects === false && ($redirected || $response->getStatusCode() >= 300)) {
            throw new RuntimeException('Unable to get the key set: redirects are refused.', $response->getStatusCode());
        }
        if ($this->followRedirects === null && $redirected) {
            trigger_deprecation(
                'web-token/jwt-framework',
                '4.3.0',
                'Fetching a key set through a redirect is deprecated and "%s" will refuse redirects by default in 5.0.0. Use the URL the redirect leads to, or pass true as the second argument of the constructor to keep following redirects, or false to refuse them. With the bundle, set the "jose.jku_factory.follow_redirects" option.',
                self::class
            );
        }

        return $response->getContent();
    }
}

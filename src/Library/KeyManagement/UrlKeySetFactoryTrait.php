<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Jose\Component\Core\Exception\RuntimeException;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use function hash;
use function is_string;
use function trigger_deprecation;

/**
 * Fetches the document a "jku" or a "x5u" header parameter points to.
 *
 * This is the shared implementation of JKUFactory and X5UFactory, which used to inherit it from UrlKeySetFactory.
 * That class is deprecated and removed in 5.0.0; a trait carries the same code without giving the two factories a
 * base class they would then have to keep. It is an implementation detail of those two classes: it is not covered
 * by the backward compatibility promise and must not be used outside of this package.
 *
 * @internal
 *
 * @see \Jose\Tests\Component\KeyManagement\UrlKeySetFactoryTest
 */
trait UrlKeySetFactoryTrait
{
    private readonly HttpClientInterface $client;

    private ?CacheItemPoolInterface $cacheItemPool = null;

    private int $expiresAfter = 3600;

    public function __construct(HttpClientInterface $client)
    {
        $this->client = $client;
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
     * @param array<string, string|string[]> $header
     */
    protected function getContent(string $url, array $header = []): string
    {
        if ($this->cacheItemPool === null) {
            return $this->sendRequest($url, $header);
        }

        $item = $this->cacheItemPool->getItem(hash('xxh128', $url));
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
     * @param array<string, string|string[]> $header
     */
    private function sendRequest(string $url, array $header): string
    {
        $response = $this->client->request('GET', $url, [
            'headers' => $header,
        ]);

        if ($response->getStatusCode() >= 400) {
            throw new RuntimeException('Unable to get the key set.', $response->getStatusCode());
        }

        return $response->getContent();
    }
}

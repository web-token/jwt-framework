<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Symfony\Contracts\HttpClient\HttpClientInterface;
use function trigger_deprecation;

/**
 * Base class JKUFactory and X5UFactory used to extend.
 *
 * Those two classes now carry their own implementation, so nothing in this package extends this one any more and
 * neither of them emits the deprecation below. What is deprecated is this class as a public extension point: it
 * never had a behaviour of its own beyond fetching a URL and caching the response, and the cache it offers -
 * a PSR-6 pool with a fixed lifetime, unaware of the cache directives of the endpoint - is better handled by the
 * HTTP client it is given.
 *
 * @deprecated since 4.3.0 and will be removed in 5.0.0. Use JKUFactory or X5UFactory, which no longer extend this
 *             class, or write a factory of your own: an HTTP client is all that is needed to fetch the document.
 */
abstract class UrlKeySetFactory
{
    use UrlKeySetFactoryTrait;

    public function __construct(HttpClientInterface $client)
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The class "%s" is deprecated and will be removed in 5.0.0. "%s" extends it: use "%s" or "%s", which do not extend it any more, or fetch the document with the HTTP client directly.',
            self::class,
            static::class,
            JKUFactory::class,
            X5UFactory::class
        );

        $this->client = $client;
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Symfony\Contracts\HttpClient\HttpClientInterface;
use function trigger_deprecation;

/**
 * Base class of JKUFactory and X5UFactory.
 *
 * Those two classes still extend it, so that the code typed against this class keeps receiving them, but they carry
 * their own implementation: they never run the constructor below and neither of them emits its deprecation. What is
 * deprecated is this class as a public extension point: it never had a behaviour of its own beyond fetching a URL and
 * caching the response, and the cache it offers - a PSR-6 pool with a fixed lifetime, unaware of the cache directives
 * of the endpoint - is better handled by the HTTP client it is given.
 *
 * @deprecated since 4.3.0 and will be removed in 5.0.0. Use JKUFactory or X5UFactory and type against them, or write
 *             a factory of your own: an HTTP client is all that is needed to fetch the document. In 5.0.0, JKUFactory
 *             and X5UFactory no longer extend this class.
 */
abstract class UrlKeySetFactory
{
    use UrlKeySetFactoryTrait;

    /**
     * Redirects are followed as before, without the deprecation of JKUFactory and X5UFactory: this class is removed
     * in 5.0.0.
     */
    public function __construct(HttpClientInterface $client)
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The class "%s" is deprecated and will be removed in 5.0.0. "%s" extends it: use "%s" or "%s" instead, or fetch the document with the HTTP client directly.',
            self::class,
            static::class,
            JKUFactory::class,
            X5UFactory::class
        );

        $this->client = $client;
        $this->followRedirects = true;
        $this->allowLargeKeySets = null;
    }
}

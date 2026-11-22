<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\JWKSet;
use function is_array;

/**
 * Extends the deprecated UrlKeySetFactory only for the code typed against that class: the fetching code comes from
 * UrlKeySetFactoryTrait, so the constructor of UrlKeySetFactory never runs and its deprecation is not triggered. In
 * 5.0.0, UrlKeySetFactory is removed and this class no longer extends it.
 *
 * @see \Jose\Tests\Component\KeyManagement\UrlKeySetFactoryTest
 */
class JKUFactory extends UrlKeySetFactory
{
    use UrlKeySetFactoryTrait;

    /**
     * This method will try to fetch the url a retrieve the key set. Throws an exception in case of failure.
     *
     * @param array<string, string|string[]> $header
     */
    public function loadFromUrl(string $url, array $header = []): JWKSet
    {
        $content = $this->getContent($url, $header);
        $data = $this->decodeKeySet($content);
        if (! is_array($data)) {
            throw new RuntimeException('Invalid content.');
        }

        return JWKSet::createFromKeyData($data);
    }
}

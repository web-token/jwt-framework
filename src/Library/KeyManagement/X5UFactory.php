<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;
use function assert;
use function is_array;
use function is_string;

/**
 * Extends the deprecated UrlKeySetFactory only for the code typed against that class: the fetching code comes from
 * UrlKeySetFactoryTrait, so the constructor of UrlKeySetFactory never runs and its deprecation is not triggered. In
 * 5.0.0, UrlKeySetFactory is removed and this class no longer extends it.
 *
 * @see \Jose\Tests\Component\KeyManagement\UrlKeySetFactoryTest
 */
class X5UFactory extends UrlKeySetFactory
{
    use UrlKeySetFactoryTrait;

    /**
     * This method will try to fetch the url a retrieve the key set. Throws an exception in case of failure.
     * An entry starting with "file://" is wrapped as well: OpenSSL would open the file it names.
     *
     * @param array<string, string|string[]> $header
     */
    public function loadFromUrl(string $url, array $header = []): JWKSet
    {
        $content = $this->getContent($url, $header);
        $data = JsonConverter::decode($content);
        if (! is_array($data)) {
            throw new RuntimeException('Invalid content.');
        }

        $keys = [];
        foreach ($data as $kid => $cert) {
            assert(is_string($cert), 'Invalid content.');
            if (! str_contains($cert, '-----BEGIN CERTIFICATE-----') || str_starts_with($cert, 'file://')) {
                $cert = '-----BEGIN CERTIFICATE-----' . "\n" . $cert . "\n" . '-----END CERTIFICATE-----';
            }
            $jwk = KeyConverter::loadKeyFromCertificate($cert);
            if (is_string($kid)) {
                $jwk['kid'] = $kid;
                $keys[$kid] = new JWK($jwk);
            } else {
                $keys[] = new JWK($jwk);
            }
        }

        return new JWKSet($keys);
    }
}

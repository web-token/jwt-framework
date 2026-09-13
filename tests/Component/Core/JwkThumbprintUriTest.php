<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\JwkThumbprintUri;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class JwkThumbprintUriTest extends TestCase
{
    private const RFC9278_EXAMPLE = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    #[Test]
    public function theRfc9278ExampleIsProduced(): void
    {
        $uri = JwkThumbprintUri::fromKey(self::rfc7638Key());

        static::assertSame(self::RFC9278_EXAMPLE, $uri->toString());
        static::assertSame(self::RFC9278_EXAMPLE, (string) $uri);
        static::assertSame('sha-256', $uri->hashAlgorithm());
        static::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $uri->thumbprint());
    }

    #[Test]
    public function theKeyProducesItsOwnThumbprintUri(): void
    {
        static::assertSame(self::RFC9278_EXAMPLE, self::rfc7638Key()->thumbprintUri());
        static::assertSame(self::RFC9278_EXAMPLE, self::rfc7638Key()->thumbprintUri('sha-256'));
    }

    #[Test]
    public function theUriOnlyDependsOnTheRfc7638Members(): void
    {
        $key = self::rfc7638Key();
        $bareKey = new JWK([
            'kty' => 'RSA',
            'n' => $key->get('n'),
            'e' => $key->get('e'),
        ]);

        static::assertSame($key->thumbprintUri(), $bareKey->thumbprintUri());
    }

    #[Test]
    #[DataProvider('supportedHashAlgorithms')]
    public function aUriIsProducedAndParsedForEverySupportedHashAlgorithm(string $hashAlgorithm): void
    {
        $key = self::rfc7638Key();
        $uri = JwkThumbprintUri::fromKey($key, $hashAlgorithm);

        static::assertSame($hashAlgorithm, $uri->hashAlgorithm());
        static::assertStringStartsWith('urn:ietf:params:oauth:jwk-thumbprint:' . $hashAlgorithm . ':', $uri->toString());

        $parsed = JwkThumbprintUri::parse($uri->toString());
        static::assertSame($hashAlgorithm, $parsed->hashAlgorithm());
        static::assertSame($uri->thumbprint(), $parsed->thumbprint());
        static::assertTrue($parsed->matches($key));
        static::assertTrue(JwkThumbprintUri::isValid($uri->toString()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function supportedHashAlgorithms(): iterable
    {
        foreach (JwkThumbprintUri::hashAlgorithms() as $hashAlgorithm) {
            yield $hashAlgorithm => [$hashAlgorithm];
        }
    }

    #[Test]
    public function theSupportedHashAlgorithmsAreTheIanaNamesPhpCanCompute(): void
    {
        static::assertSame(
            ['sha-256', 'sha-384', 'sha-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'],
            JwkThumbprintUri::hashAlgorithms()
        );
    }

    #[Test]
    public function theSha512AndSha3UrisCarryTheExpectedThumbprints(): void
    {
        $key = self::rfc7638Key();

        static::assertSame(
            'urn:ietf:params:oauth:jwk-thumbprint:sha-512:DpvEwocfn3FjeWWQjcJHzWrpKTIymKwgoL1xVgQcud48-qZDSRCr1zfWZQdHAJn_ciqXqPTSARyg-L-NyNGpVA',
            $key->thumbprintUri('sha-512')
        );
        static::assertSame(
            'urn:ietf:params:oauth:jwk-thumbprint:sha3-256:OxvsYwfbJzpVoasK4e0ajHAApL0JyLLZxbmJJynhQ3A',
            $key->thumbprintUri('sha3-256')
        );
    }

    #[Test]
    #[DataProvider('refusedHashAlgorithms')]
    public function anUnsupportedHashAlgorithmIsRefusedWhenProducing(string $hashAlgorithm): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessage(
            'The hash algorithm "' . $hashAlgorithm . '" is not supported for a JWK Thumbprint URI.'
        );

        self::rfc7638Key()->thumbprintUri($hashAlgorithm);
    }

    #[Test]
    #[DataProvider('refusedHashAlgorithms')]
    public function anUnsupportedHashAlgorithmIsRefusedWhenParsing(string $hashAlgorithm): void
    {
        $uri = 'urn:ietf:params:oauth:jwk-thumbprint:' . $hashAlgorithm . ':NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
        static::assertFalse(JwkThumbprintUri::isValid($uri));

        $this->expectException(UnsupportedAlgorithmException::class);
        JwkThumbprintUri::parse($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function refusedHashAlgorithms(): iterable
    {
        yield 'md5' => ['md5'];
        yield 'sha-1' => ['sha-1'];
        yield 'the PHP name instead of the IANA one' => ['sha256'];
        yield 'a truncated variant of the registry' => ['sha-256-128'];
        yield 'a registered function PHP cannot compute' => ['blake2b-256'];
        yield 'upper case' => ['SHA-256'];
        yield 'unknown' => ['foo'];
    }

    #[Test]
    #[DataProvider('malformedUris')]
    public function aMalformedUriIsRefused(string $uri, string $message): void
    {
        static::assertFalse(JwkThumbprintUri::isValid($uri));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        JwkThumbprintUri::parse($uri);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedUris(): iterable
    {
        yield 'not a URN' => ['https://example.com/jwk-thumbprint:sha-256:abc', 'The URI is not a JWK Thumbprint URI.'];
        yield 'another URN' => ['urn:ietf:params:oauth:token-type:jwt', 'The URI is not a JWK Thumbprint URI.'];
        yield 'upper case prefix' => [
            'URN:IETF:PARAMS:OAUTH:JWK-THUMBPRINT:sha-256:abc',
            'The URI is not a JWK Thumbprint URI.',
        ];
        yield 'prefix only' => [
            'urn:ietf:params:oauth:jwk-thumbprint:',
            'must be of the form "urn:ietf:params:oauth:jwk-thumbprint:<hash-alg>:<thumbprint>"',
        ];
        yield 'no thumbprint' => [
            'urn:ietf:params:oauth:jwk-thumbprint:sha-256',
            'must be of the form "urn:ietf:params:oauth:jwk-thumbprint:<hash-alg>:<thumbprint>"',
        ];
        yield 'empty thumbprint' => [
            'urn:ietf:params:oauth:jwk-thumbprint:sha-256:',
            'must be of the form "urn:ietf:params:oauth:jwk-thumbprint:<hash-alg>:<thumbprint>"',
        ];
        yield 'empty hash algorithm' => [
            'urn:ietf:params:oauth:jwk-thumbprint::abc',
            'must be of the form "urn:ietf:params:oauth:jwk-thumbprint:<hash-alg>:<thumbprint>"',
        ];
        yield 'too many components' => [
            'urn:ietf:params:oauth:jwk-thumbprint:sha-256:abc:def',
            'must be of the form "urn:ietf:params:oauth:jwk-thumbprint:<hash-alg>:<thumbprint>"',
        ];
        yield 'thumbprint not base64url' => [
            'urn:ietf:params:oauth:jwk-thumbprint:sha-256:abc+def/ghi=',
            'The thumbprint of the JWK Thumbprint URI is not base64url encoded.',
        ];
    }

    #[Test]
    public function aUriDoesNotMatchAnotherKey(): void
    {
        $uri = JwkThumbprintUri::parse(self::RFC9278_EXAMPLE);

        static::assertTrue($uri->matches(self::rfc7638Key()));
        static::assertFalse($uri->matches(self::ecKey()));
    }

    #[Test]
    public function theMatchDependsOnTheHashAlgorithmOfTheUri(): void
    {
        $key = self::rfc7638Key();
        $uri = JwkThumbprintUri::parse(
            'urn:ietf:params:oauth:jwk-thumbprint:sha-512:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'
        );

        static::assertFalse($uri->matches($key));
    }

    #[Test]
    public function theKeySetReturnsTheKeyIdentifiedByTheUri(): void
    {
        $rsaKey = self::rfc7638Key();
        $ecKey = self::ecKey();
        $keySet = new JWKSet([$ecKey, $rsaKey]);

        static::assertSame($rsaKey, $keySet->selectKeyByThumbprintUri(self::RFC9278_EXAMPLE));
        static::assertSame($ecKey, $keySet->selectKeyByThumbprintUri($ecKey->thumbprintUri('sha3-512')));
        static::assertSame($rsaKey, $keySet->selectKeyByThumbprintUri(JwkThumbprintUri::parse(self::RFC9278_EXAMPLE)));
    }

    #[Test]
    public function theKeySetReturnsNullWhenNoKeyMatchesTheUri(): void
    {
        $keySet = new JWKSet([self::ecKey()]);

        static::assertNull($keySet->selectKeyByThumbprintUri(self::RFC9278_EXAMPLE));
        static::assertNull((new JWKSet([]))->selectKeyByThumbprintUri(self::RFC9278_EXAMPLE));
    }

    #[Test]
    public function theKeySetSkipsAKeyWhoseThumbprintCannotBeComputed(): void
    {
        $rsaKey = self::rfc7638Key();
        $brokenKey = new JWK([
            'kty' => 'oct',
            'k' => "\xB1\x31",
        ]);
        $keySet = new JWKSet([$brokenKey, $rsaKey]);

        static::assertSame($rsaKey, $keySet->selectKeyByThumbprintUri(self::RFC9278_EXAMPLE));
    }

    #[Test]
    public function theKeySetRefusesAMalformedUri(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new JWKSet([self::ecKey()]))->selectKeyByThumbprintUri('urn:ietf:params:oauth:jwk-thumbprint:sha-256');
    }

    /**
     * The RSA key of RFC 7638 section 3.1, reused by the RFC 9278 section 3 example.
     */
    private static function rfc7638Key(): JWK
    {
        return new JWK([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
            'alg' => 'RS256',
            'kid' => '2011-04-29',
        ]);
    }

    private static function ecKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sig',
        ]);
    }
}

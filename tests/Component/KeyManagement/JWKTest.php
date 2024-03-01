<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class JWKTest extends TestCase
{
    #[Test]
    public function key(): void
    {
        $jwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        static::assertSame('EC', $jwk->get('kty'));
        static::assertSame('ES256', $jwk->get('alg'));
        static::assertSame('sign', $jwk->get('use'));
        static::assertFalse($jwk->has('kid'));
        static::assertSame(['sign'], $jwk->get('key_ops'));
        static::assertSame('P-256', $jwk->get('crv'));
        static::assertFalse($jwk->has('x5u'));
        static::assertFalse($jwk->has('x5c'));
        static::assertFalse($jwk->has('x5t'));
        static::assertFalse($jwk->has('x5t#256'));
        static::assertSame('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', $jwk->get('x'));
        static::assertSame('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', $jwk->get('y'));
        static::assertSame(
            '{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","bar":"plic"}',
            json_encode($jwk, JSON_THROW_ON_ERROR)
        );
    }

    #[Test]
    public function badConstruction(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The parameter "kty" is mandatory.');

        new JWK([]);
    }

    #[Test]
    public function badCall(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value identified by "ABCD" does not exist.');

        $jwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        $jwk->get('ABCD');
    }

    #[Test]
    public function keySet(): void
    {
        $jwk1 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'kid' => '0123456789',
        ]);

        $jwk2 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $jwkset = new JWKSet([$jwk1]);
        $jwkset = $jwkset->with($jwk2);

        static::assertSame(
            '{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","use":"sign","key_ops":["verify"],"alg":"ES256","kid":"9876543210"}]}',
            json_encode($jwkset, JSON_THROW_ON_ERROR)
        );
        static::assertCount(2, $jwkset);
        static::assertSame(2, $jwkset->count());
        static::assertTrue($jwkset->has('0123456789'));
        static::assertTrue($jwkset->has('9876543210'));
        static::assertFalse($jwkset->has(0));

        foreach ($jwkset as $key) {
            static::assertSame('EC', $key->get('kty'));
        }

        static::assertSame('9876543210', $jwkset->get('9876543210')->get('kid'));
        $jwkset = $jwkset->without('9876543210');
        $jwkset = $jwkset->without('9876543210');

        static::assertCount(1, $jwkset);
        static::assertSame(1, $jwkset->count());

        $jwkset = $jwkset->without('0123456789');
        static::assertCount(0, $jwkset);
        static::assertSame(0, $jwkset->count());
    }

    #[Test]
    public function keySet2(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Undefined index.');

        $jwk1 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'kid' => '0123456789',
        ]);

        $jwk2 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $jwkset = new JWKSet([$jwk1, $jwk2]);

        $jwkset->get(2);
    }

    #[Test]
    public function privateToPublic(): void
    {
        $private = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $public = $private->toPublic();

        static::assertSame(json_encode([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]), json_encode($public, JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function loadCertificateChain(): void
    {
        $key = JWKFactory::createFromCertificateFile(
            __DIR__ . '/Chain/google.crt',
            [
                'kid' => 'From www.google.com',
            ]
        );

        static::assertSame(
            '178f7e93a74ed73d88c29042220b9ae6e4b371cd',
            mb_strtolower(bin2hex(Base64UrlSafe::decode($key->get('x5t'))))
        );
        static::assertEqualsCanonicalizing([
            'kty' => 'RSA',
            'n' => 'nCoEd1zYUJE6BqOC4NhQSLyJP_EZcBqIRn7gj8Xxic4h7lr-YQ23MkSJoHQLU09VpM6CYpXu61lfxuEFgBLEXpQ_vFtIOPRT9yTm-5HpFcTP9FMN9Er8n1Tefb6ga2-HwNBQHygwA0DaCHNRbH__OjynNwaOvUsRBOt9JN7m-fwxcfuU1WDzLkqvQtLL6sRqGrLMU90VS4sfyBlhH82dqD5jK4Q1aWWEyBnFRiL4U5W-44BKEMYq7LqXIBHHOZkQBKDwYXqVJYxOUnXitu0IyhT8ziJqs07PRgOXlwN-wLHee69FM8-6PnG33vQlJcINNYmdnfsOEXmJHjfFr45yaQ',
            'e' => 'AQAB',
            'x5t' => 'F49-k6dO1z2IwpBCIgua5uSzcc0',
            'x5t#256' => 'pBJP2vnKx7ruHKsy4yJddGUAwJ888-uyU-8_uwiK_TQ',
            'kid' => 'From www.google.com',
            'x5c' => [
                'MIID8DCCAtigAwIBAgIDAjqDMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9iYWwgQ0EwHhcNMTMwNDA1MTUxNTU2WhcNMTYxMjMxMjM1OTU5WjBJMQswCQYDVQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVybmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NPVaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtvh8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rEahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZEASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXCDTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYDVR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQMA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEAqvqpIM1qZ4PtXtR+3h3Ef+AlBgDFJPupyC1tft6dgmUsgWM0Zj7pUsIItMsv91+ZOmqcUHqFBYx90SpIhNMJbHzCzTWf84LuUt5oX+QAihcglvcpjZpNy6jehsgNb1aHA30DP9z6eX0hGfnIOi9RdozHQZJxjyXON/hKTAAj78Q1EK7gI4BzfE00LshukNYQHpmEcxpw8u1VDu4XBupn7jLrLN1nBz/2i8Jw3lsA5rsb0zYaImxssDVCbJAJPZPpZAkiDoUGn8JzIdPmX4DkjYUiOnMDsWCOrmji9D6X52ASCWg23jrW4kOVWzeBkoEfu43XrVJkFleW2V40fsg12A==',
            ],
        ], $key->all());
    }

    #[Test]
    public function theRSAKeyIsCorrectlyConvertedIntoPEM(): void
    {
        // Given
        $key = new JWK([
            'kty' => 'RSA',
            'n' => 'z62tHQzm4fDHipqlcrNhC1gUdn0N38pmlcQbVlLvtZf1aRm1OO43cB9YQyWr1MsTrYH4nyWZDMPIGY_BsIfYw1lp9fo2D1tpG2vtCaKRETVimu-N9DySQ9vYs6n8lG0vXy_spK7sGrOLFooijDSt0LYrYrZY9UI3OkyEAKUbZLJhxi7nT3CPtMCYDUMIIt1LgWdR6-ha5fQQrWF7YbyiMNmITg64DZ9yof4-OfouNE2dFXGl3Nr92HaugXbMZF_pILpcB61NT215aql1ifVXvEyGAsyPBnxIcjadfcgQ0UUtepN2BJRj_pq55jfQR2Nl0e11JeKEIPR3ypqvKeDI10Cl-qr9GpU0rFfw2vcp8IHTNrAeam4nTRDVCmXGwiMaLifAKbvfGwxaA2mHbO5i4669KiPf_lXAQz9FzAZZRwpdM1FTB9BlB5R-JgvtBabP5ZGhqlUOgkJM_4UfrpcIkS8Ub4Y60QvPkInCGBMHNdUqpJUkLoA5Mddl8hVW-cMjC2qCckgT1KgZxIsZTgOJXCARX1IObFJNoinxYJ5SNX9bCSRtgefuBKE7BSNukAkHyBPf---kEi9GbYXzlJr-yCMAIsA0UoiEx264hkAF9zF-N1yRhS_QmrhzU5hpj1IE8WRCqyIZV8f_IbSGXBue7MmgknLVRWHuGqehkTSfiNE',
            'e' => 'AQAB',
        ]);

        // When
        $pem = RSAKey::createFromJWK($key)->toPEM();

        // Then
        static::assertSame('-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz62tHQzm4fDHipqlcrNh
C1gUdn0N38pmlcQbVlLvtZf1aRm1OO43cB9YQyWr1MsTrYH4nyWZDMPIGY/BsIfY
w1lp9fo2D1tpG2vtCaKRETVimu+N9DySQ9vYs6n8lG0vXy/spK7sGrOLFooijDSt
0LYrYrZY9UI3OkyEAKUbZLJhxi7nT3CPtMCYDUMIIt1LgWdR6+ha5fQQrWF7Ybyi
MNmITg64DZ9yof4+OfouNE2dFXGl3Nr92HaugXbMZF/pILpcB61NT215aql1ifVX
vEyGAsyPBnxIcjadfcgQ0UUtepN2BJRj/pq55jfQR2Nl0e11JeKEIPR3ypqvKeDI
10Cl+qr9GpU0rFfw2vcp8IHTNrAeam4nTRDVCmXGwiMaLifAKbvfGwxaA2mHbO5i
4669KiPf/lXAQz9FzAZZRwpdM1FTB9BlB5R+JgvtBabP5ZGhqlUOgkJM/4UfrpcI
kS8Ub4Y60QvPkInCGBMHNdUqpJUkLoA5Mddl8hVW+cMjC2qCckgT1KgZxIsZTgOJ
XCARX1IObFJNoinxYJ5SNX9bCSRtgefuBKE7BSNukAkHyBPf+++kEi9GbYXzlJr+
yCMAIsA0UoiEx264hkAF9zF+N1yRhS/QmrhzU5hpj1IE8WRCqyIZV8f/IbSGXBue
7MmgknLVRWHuGqehkTSfiNECAwEAAQ==
-----END PUBLIC KEY-----', $pem);
    }
}

<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use function count;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use const PHP_EOL;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class JWKTest extends TestCase
{
    /**
     * @test
     */
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

    /**
     * @test
     */
    public function badConstruction(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The parameter "kty" is mandatory.');

        new JWK([]);
    }

    /**
     * @test
     */
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

    /**
     * @test
     */
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
        static::assertSame(2, count($jwkset));
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

        static::assertSame(1, count($jwkset));
        static::assertSame(1, $jwkset->count());

        $jwkset = $jwkset->without('0123456789');
        static::assertSame(0, count($jwkset));
        static::assertSame(0, $jwkset->count());
    }

    /**
     * @test
     */
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

    /**
     * @test
     */
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

    /**
     * @test
     */
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
        static::assertEqualsCanonicalizing(
            [
                'kty' => 'RSA',
                'n' => 'nCoEd1zYUJE6BqOC4NhQSLyJP_EZcBqIRn7gj8Xxic4h7lr-YQ23MkSJoHQLU09VpM6CYpXu61lfxuEFgBLEXpQ_vFtIOPRT9yTm-5HpFcTP9FMN9Er8n1Tefb6ga2-HwNBQHygwA0DaCHNRbH__OjynNwaOvUsRBOt9JN7m-fwxcfuU1WDzLkqvQtLL6sRqGrLMU90VS4sfyBlhH82dqD5jK4Q1aWWEyBnFRiL4U5W-44BKEMYq7LqXIBHHOZkQBKDwYXqVJYxOUnXitu0IyhT8ziJqs07PRgOXlwN-wLHee69FM8-6PnG33vQlJcINNYmdnfsOEXmJHjfFr45yaQ',
                'e' => 'AQAB',
                'x5t' => 'F49-k6dO1z2IwpBCIgua5uSzcc0',
                'x5t#256' => 'pBJP2vnKx7ruHKsy4yJddGUAwJ888-uyU-8_uwiK_TQ',
                'kid' => 'From www.google.com',
                'x5c' => [
                    'MIID8DCCAtigAwIBAgIDAjqDMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT' . PHP_EOL . 'MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i' . PHP_EOL . 'YWwgQ0EwHhcNMTMwNDA1MTUxNTU2WhcNMTYxMjMxMjM1OTU5WjBJMQswCQYDVQQG' . PHP_EOL . 'EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy' . PHP_EOL . 'bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB' . PHP_EOL . 'AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP' . PHP_EOL . 'VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv' . PHP_EOL . 'h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE' . PHP_EOL . 'ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ' . PHP_EOL . 'EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC' . PHP_EOL . 'DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7' . PHP_EOL . 'qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYD' . PHP_EOL . 'VR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDov' . PHP_EOL . 'L2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCig' . PHP_EOL . 'JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQ' . PHP_EOL . 'MA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEAqvqpIM1qZ4PtXtR+' . PHP_EOL . '3h3Ef+AlBgDFJPupyC1tft6dgmUsgWM0Zj7pUsIItMsv91+ZOmqcUHqFBYx90SpI' . PHP_EOL . 'hNMJbHzCzTWf84LuUt5oX+QAihcglvcpjZpNy6jehsgNb1aHA30DP9z6eX0hGfnI' . PHP_EOL . 'Oi9RdozHQZJxjyXON/hKTAAj78Q1EK7gI4BzfE00LshukNYQHpmEcxpw8u1VDu4X' . PHP_EOL . 'Bupn7jLrLN1nBz/2i8Jw3lsA5rsb0zYaImxssDVCbJAJPZPpZAkiDoUGn8JzIdPm' . PHP_EOL . 'X4DkjYUiOnMDsWCOrmji9D6X52ASCWg23jrW4kOVWzeBkoEfu43XrVJkFleW2V40' . PHP_EOL . 'fsg12A==',
                ],
            ],
            $key->all()
        );
    }
}

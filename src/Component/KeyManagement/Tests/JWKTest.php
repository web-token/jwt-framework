<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\Tests;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group Unit
 * @group JWK
 */
class JWKTest extends TestCase
{
    public function testKey()
    {
        $jwk = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'bar'     => 'plic',
        ]);

        self::assertEquals('EC', $jwk->get('kty'));
        self::assertEquals('ES256', $jwk->get('alg'));
        self::assertEquals('sign', $jwk->get('use'));
        self::assertFalse($jwk->has('kid'));
        self::assertEquals(['sign'], $jwk->get('key_ops'));
        self::assertEquals('P-256', $jwk->get('crv'));
        self::assertFalse($jwk->has('x5u'));
        self::assertFalse($jwk->has('x5c'));
        self::assertFalse($jwk->has('x5t'));
        self::assertFalse($jwk->has('x5t#256'));
        self::assertEquals('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', $jwk->get('x'));
        self::assertEquals('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', $jwk->get('y'));
        self::assertEquals('{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","bar":"plic"}', json_encode($jwk));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The parameter "kty" is mandatory.
     */
    public function testBadConstruction()
    {
        JWK::create([]);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The value identified by "ABCD" does not exist.
     */
    public function testBadCall()
    {
        $jwk = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'bar'     => 'plic',
        ]);

        $jwk->get('ABCD');
    }

    public function testKeySet()
    {
        $jwk1 = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'kid'     => '0123456789',
        ]);

        $jwk2 = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use'     => 'sign',
            'key_ops' => ['verify'],
            'alg'     => 'ES256',
            'kid'     => '9876543210',
        ]);

        $jwkset = JWKSet::createFromKeys([$jwk1]);
        $jwkset = $jwkset->with($jwk2);

        self::assertEquals('{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","use":"sign","key_ops":["verify"],"alg":"ES256","kid":"9876543210"}]}', json_encode($jwkset));
        self::assertEquals(2, count($jwkset));
        self::assertEquals(2, $jwkset->count());
        self::assertTrue($jwkset->has('0123456789'));
        self::assertTrue($jwkset->has('9876543210'));
        self::assertFalse($jwkset->has(0));

        foreach ($jwkset as $key) {
            self::assertEquals('EC', $key->get('kty'));
        }

        self::assertEquals('9876543210', $jwkset->get('9876543210')->get('kid'));
        $jwkset = $jwkset->without('9876543210');
        $jwkset = $jwkset->without('9876543210');

        self::assertEquals(1, count($jwkset));
        self::assertEquals(1, $jwkset->count());
        self::assertInstanceOf(JWK::class, $jwkset->get('0123456789'));

        $jwkset = $jwkset->without('0123456789');
        self::assertEquals(0, count($jwkset));
        self::assertEquals(0, $jwkset->count());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Undefined index.
     */
    public function testKeySet2()
    {
        $jwk1 = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['sign'],
            'alg'     => 'ES256',
            'kid'     => '0123456789',
        ]);

        $jwk2 = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use'     => 'sign',
            'key_ops' => ['verify'],
            'alg'     => 'ES256',
            'kid'     => '9876543210',
        ]);

        $jwkset = JWKSet::createFromKeys([$jwk1, $jwk2]);

        $jwkset->get(2);
    }

    public function testPrivateToPublic()
    {
        $private = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use'     => 'sign',
            'key_ops' => ['verify'],
            'alg'     => 'ES256',
            'kid'     => '9876543210',
        ]);

        $public = $private->toPublic();

        self::assertEquals(json_encode([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use'     => 'sign',
            'key_ops' => ['verify'],
            'alg'     => 'ES256',
            'kid'     => '9876543210',
        ]), json_encode($public));
    }

    public function testLoadCertificateChain()
    {
        $key = JWKFactory::createFromCertificateFile(
            __DIR__.'/Chain/google.crt',
            [
                'kid' => 'From www.google.com',
            ]
        );

        self::assertEquals(
            '178f7e93a74ed73d88c29042220b9ae6e4b371cd',
            strtolower(bin2hex(Base64Url::decode($key->get('x5t'))))
        );
        self::assertEquals([
                'kty'     => 'RSA',
                'n'       => 'nCoEd1zYUJE6BqOC4NhQSLyJP_EZcBqIRn7gj8Xxic4h7lr-YQ23MkSJoHQLU09VpM6CYpXu61lfxuEFgBLEXpQ_vFtIOPRT9yTm-5HpFcTP9FMN9Er8n1Tefb6ga2-HwNBQHygwA0DaCHNRbH__OjynNwaOvUsRBOt9JN7m-fwxcfuU1WDzLkqvQtLL6sRqGrLMU90VS4sfyBlhH82dqD5jK4Q1aWWEyBnFRiL4U5W-44BKEMYq7LqXIBHHOZkQBKDwYXqVJYxOUnXitu0IyhT8ziJqs07PRgOXlwN-wLHee69FM8-6PnG33vQlJcINNYmdnfsOEXmJHjfFr45yaQ',
                'e'       => 'AQAB',
                'x5t'     => 'F49-k6dO1z2IwpBCIgua5uSzcc0',
                'x5t#256' => 'pBJP2vnKx7ruHKsy4yJddGUAwJ888-uyU-8_uwiK_TQ',
                'kid'     => 'From www.google.com',
                'x5c'     => ['MIID8DCCAtigAwIBAgIDAjqDMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT'.PHP_EOL.'MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i'.PHP_EOL.'YWwgQ0EwHhcNMTMwNDA1MTUxNTU2WhcNMTYxMjMxMjM1OTU5WjBJMQswCQYDVQQG'.PHP_EOL.'EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy'.PHP_EOL.'bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB'.PHP_EOL.'AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP'.PHP_EOL.'VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv'.PHP_EOL.'h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE'.PHP_EOL.'ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ'.PHP_EOL.'EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC'.PHP_EOL.'DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7'.PHP_EOL.'qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYD'.PHP_EOL.'VR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDov'.PHP_EOL.'L2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCig'.PHP_EOL.'JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQ'.PHP_EOL.'MA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEAqvqpIM1qZ4PtXtR+'.PHP_EOL.'3h3Ef+AlBgDFJPupyC1tft6dgmUsgWM0Zj7pUsIItMsv91+ZOmqcUHqFBYx90SpI'.PHP_EOL.'hNMJbHzCzTWf84LuUt5oX+QAihcglvcpjZpNy6jehsgNb1aHA30DP9z6eX0hGfnI'.PHP_EOL.'Oi9RdozHQZJxjyXON/hKTAAj78Q1EK7gI4BzfE00LshukNYQHpmEcxpw8u1VDu4X'.PHP_EOL.'Bupn7jLrLN1nBz/2i8Jw3lsA5rsb0zYaImxssDVCbJAJPZPpZAkiDoUGn8JzIdPm'.PHP_EOL.'X4DkjYUiOnMDsWCOrmji9D6X52ASCWg23jrW4kOVWzeBkoEfu43XrVJkFleW2V40'.PHP_EOL.'fsg12A=='],
            ],
            $key->all()
        );
    }
}

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\KeyManagement;

use Http\Mock\Client;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\X5UFactory;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * @group unit
 * @group UrlKeySetFactory
 *
 * @internal
 */
class UrlKeySetFactoryTest extends TestCase
{
    /**
     * @var Psr17Factory
     */
    private $messageFactory;

    /**
     * @var null|JKUFactory
     */
    private $jkuFactory;

    /**
     * @var null|X5UFactory
     */
    private $x5uFactory;

    /**
     * @var null|Client
     */
    private $httpClient;

    protected function setUp(): void
    {
        $this->messageFactory = new Psr17Factory();
    }

    /**
     * @test
     */
    public function iCanGetAKeySetFromAJWKUrl(): void
    {
        $response = $this->messageFactory->createResponse(200);
        $response->getBody()->write('{"keys": [{"kty": "RSA","alg": "RS256","use": "sig","kid": "acde8d7c1997d82dcf5d5ed2858ac8d060cd3ca9","n": "kfQP58EQpxAqZUCiGolkyCio8S3hG9HTMfQpB7VVDB69mK3AN68ZmWeGTIvDnbcslQ1TEhjZ8bKJwWHFlyoJOxeGaEsn0G3xAmPeUW8WjS2tLTKx8DUYOAgto9VOWip5dngZVMrCL85fPk-jiKEL3ODsyddZiOOhBEjapco_RTDPVurVreDnG6mbScCslHda5T6KudyFOQLD77BulIENlpE5Lxh3KFGrGgu_RiVOf-XtHDDExiWOsaUhOSZFkecqF56upROBQRIuNqHv98icbVKRzYcDteRckJGfk12faaQhX24QCDsIrT8NHbbB9eKX7rcnDMp8GxSArct7KyOxyw","e": "AQAB"},{"kty": "RSA","alg": "RS256","use": "sig","kid": "ce760dff481ee9bca45ccab64eada328029bc0aa","n": "47QQ2Ru1h3WWxcTUbwQvhD_ncEw7avXtXDmcY_8zxC9FcPwv6GcAvjoWuF0afBNK4UoNqW9gG_eq96FnMUF0iIVkPio-h3cpOHzAhKN-LHB9UMx3WDCVYxeRjGOgKU8oLz7ioqGhyZc-oxWk0v691Ybp83OPhWa0bVAmTgSaAuPpyw-ZLg-Nb4eF---vjb1N0ptYltSOQNEZ3BK9jEbWKNHASTcTpFkigcWyLp_sFv79W_DLZEKIb4TxaoGGWA-AMiErFsAnzcU7Ia4ETyp5ucI6o4SifKzI1SKRkUTinlVnvedwXhu21HBviEe_a-fg3uYc7JTMgFNG3kQlfks8AQ","e": "AQAB"},{"kty": "RSA","alg": "RS256","use": "sig","kid": "3ce4a97d502af058eb66ac8d730a592ab7cea7f1","n": "5JjYSEt7lxpIBtnZSAta6uPZpiAFSwzRhhWdBbRr1QuEMPhBvfWsy0PArA8xx5U8AIWftTmhsTdXvkLRLrG_vT4fxjU22K2YBoeTY2v2QIvJOUyhLWOr5wVtG9iWtg86FsGv0ukEgEpx2mqIlpz0KWkEZwIhtYRTtFQh_G4QFjvyAg70iFi7BvSizfZlEDrg5-5ksia0Gy_gmjGvgTLHGBLciKo5d5Aw-DBPJqunnJacVu6rTkBF_QgsOWpO5Y8XuKbjEKNzUHSv6TxumaK7ueU1ckucdtkAHqURzEInbb3BxWYme_3JCzTDMRy4-pEoWR-NyLZwEZxxOtGFQRXhZw","e": "AQAB"}]}');
        $response->getBody()->rewind();
        $this->getHttpClient()->addResponse($response);
        $keyset = $this->getJKUFactory()->loadFromUrl('https://foo.bar/keys');

        static::assertEquals(3, $keyset->count());
    }

    /**
     * @test
     */
    public function theJWKUrlIsValidButDoesNotContainAKeySet(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid content.');

        $response = $this->messageFactory->createResponse(200);
        $response->getBody()->write('Hello World!');
        $response->getBody()->rewind();
        $this->getHttpClient()->addResponse($response);
        $this->getJKUFactory()->loadFromUrl('https://foo.bar/bad/url');
    }

    /**
     * @test
     */
    public function theUrlIsNotValidAndJWKSetCannotBeLoaded(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to get the key set.');

        $response = $this->messageFactory->createResponse(404);
        $response->getBody()->write('Not found');
        $response->getBody()->rewind();
        $this->getHttpClient()->addResponse($response);
        $this->getJKUFactory()->loadFromUrl('https://foo.bar/bad/url');
    }

    /**
     * @test
     */
    public function iCanGetAKeySetFromAX509Url(): void
    {
        $response = $this->messageFactory->createResponse(200);
        $response->getBody()->write('["MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVM\nxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR2\n8gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExM\nTYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UE\nCBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWR\nkeS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYW\nRkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlc\nnRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTt\nwY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqV\nTr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aL\nGbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo\n7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgW\nJCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAw\nEAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVH\nSMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEA\nMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWR\nkeS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2\nRhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVH\nSAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5j\nb20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggE\nBANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPI\nUyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL\n5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9\np0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsx\nuxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZ\nEjYx8WnM25sgVjOuH0aBsXBTWVU+4=","MIIE+zCCBGSgAwIBAgICAQ0wDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1Z\nhbGlDZXJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIE\nluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb\n24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8x\nIDAeBgkqhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTA0MDYyOTE3MDY\nyMFoXDTI0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZS\nBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgM\niBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN\nADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XC\nAPVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux\n6wwdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLO\ntXiEqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWo\nriMYavx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZ\nEewo+YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjggHhMIIB3TAdBgNVHQ\n4EFgQU0sSw0pHUTBFxs2HLPaH+3ahq1OMwgdIGA1UdIwSByjCBx6GBwaSBvjCBu\nzEkMCIGA1UEBxMbVmFsaUNlcnQgVmFsaWRhdGlvbiBOZXR3b3JrMRcwFQYDVQQK\nEw5WYWxpQ2VydCwgSW5jLjE1MDMGA1UECxMsVmFsaUNlcnQgQ2xhc3MgMiBQb2x\npY3kgVmFsaWRhdGlvbiBBdXRob3JpdHkxITAfBgNVBAMTGGh0dHA6Ly93d3cudm\nFsaWNlcnQuY29tLzEgMB4GCSqGSIb3DQEJARYRaW5mb0B2YWxpY2VydC5jb22CA\nQEwDwYDVR0TAQH/BAUwAwEB/zAzBggrBgEFBQcBAQQnMCUwIwYIKwYBBQUHMAGG\nF2h0dHA6Ly9vY3NwLmdvZGFkZHkuY29tMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA\n6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS9yb290LmNybD\nBLBgNVHSAERDBCMEAGBFUdIAAwODA2BggrBgEFBQcCARYqaHR0cDovL2NlcnRpZ\nmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5MA4GA1UdDwEB/wQEAwIBBjAN\nBgkqhkiG9w0BAQUFAAOBgQC1QPmnHfbq/qQaQlpE9xXUhUaJwL6e4+PrxeNYiY+\nSn1eocSxI0YGyeR+sBjUZsE4OWBsUs5iB0QQeyAfJg594RAoYC5jcdnplDQ1tgM\nQLARzLrUc+cb53S8wGd9D0VmsfSxOaFIqII6hR8INMqzW/Rn453HWkrugp++85j\n09VZw==","MIIC5zCCAlACAQEwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZXJ\n0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNT\nAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0a\nG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkq\nhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTk5MDYyNjAwMTk1NFoXDTE\n5MDYyNjAwMTk1NFowgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0IFZhbGlkYXRpb24gTm\nV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZ\nXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQD\nExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0BCQEWEWluZm9\nAdmFsaWNlcnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOOnHK5a\nvIWZJV16vYdA757tn2VUdZZUcOBVXc65g2PFxTXdMwzzjsvUGJ7SVCCSRrCl6zf\nN1SLUzm1NZ9WlmpZdRJEy0kTRxQb7XBhVQ7/nHk01xC+YDgkRoKWzk2Z/M/VXwb\nP7RfZHM047QSv4dk+NoS/zcnwbNDu+97bi5p9wIDAQABMA0GCSqGSIb3DQEBBQU\nAA4GBADt/UG9vUJSZSWI4OB9L+KXIPqeCgfYrx+jFzug6EILLGACOTb2oWH+heQ\nC1u+mNr0HZDzTuIYEZoDJJKPTEjlbVUjP9UNV+mWwD5MlM/Mtsq2azSiGM5bUMM\nj4QssxsodyamEwCW/POuZ6lcg5Ktz885hZo+L7tdEy8W9ViH0Pd"]');
        $response->getBody()->rewind();
        $this->getHttpClient()->addResponse($response);
        $keyset = $this->getX5UFactory()->loadFromUrl('https://foo.bar/keys');

        static::assertEquals(3, $keyset->count());
    }

    /**
     * @test
     */
    public function theX509UrlIsValidButDoesNotContainAKeySet(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid content.');

        $response = $this->messageFactory->createResponse(200);
        $response->getBody()->write('Hello World!');
        $response->getBody()->rewind();
        $this->getHttpClient()->addResponse($response);
        $this->getX5UFactory()->loadFromUrl('https://foo.bar/bad/url');
    }

    /**
     * @test
     */
    public function theUrlIsNotValidAndX509CertificatesCannotBeLoaded(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to get the key set.');

        $response = $this->messageFactory->createResponse(404);
        $response->getBody()->write('Not found');
        $response->getBody()->rewind();
        $this->getHttpClient()->addResponse($response);
        $this->getX5UFactory()->loadFromUrl('https://foo.bar/bad/url');
    }

    private function getJKUFactory(): JKUFactory
    {
        if (null === $this->jkuFactory) {
            $this->jkuFactory = new JKUFactory(
                $this->getHttpClient(),
                new Psr17Factory()
            );
        }

        return $this->jkuFactory;
    }

    private function getX5UFactory(): X5UFactory
    {
        if (null === $this->x5uFactory) {
            $this->x5uFactory = new X5UFactory(
                $this->getHttpClient(),
                new Psr17Factory()
            );
        }

        return $this->x5uFactory;
    }

    private function getHttpClient(): Client
    {
        if (null === $this->httpClient) {
            $this->httpClient = new Client();
        }

        return $this->httpClient;
    }
}

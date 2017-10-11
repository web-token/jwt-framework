<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\KeyManagement\Tests;

use Jose\Component\Core\JWKSet;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * @group Bundle
 * @group Functional
 */
final class JWKSetLoaderTest extends WebTestCase
{
    public function testJWKSetRouteFromConfigurationIsAvailable()
    {
        $client = static::createClient();

        $container = $client->getContainer();
        self::assertTrue($container->has('jose.key_set.jwkset1'));
        self::assertInstanceOf(JWKSet::class, $container->get('jose.key_set.jwkset1'));

        $client->request('GET', '/keys/1.jwkset');
        /** @var Response $response */
        $response = $client->getResponse();
        self::assertInstanceOf(Response::class, $response);

        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('{"keys":[{"kty":"oct","k":"dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g"},{"kty":"oct","k":"bwIAv5Nn-fo8p4LCEvM4IR9eLXgzJRs8jXCLb3xR0tDJGiZ46KheO4ip6htFKyN2aqJqlNi9-7hB6I1aLLy1IRT9-vcBoCSGu977cNAUuRLkRp7vo8s6MsxhB8WvQBDRZghV7jIYaune-3vbE7iDU2AESr8BUtorckLoO9uW__fIabaa3hJMMQIHCzYQbJKZvlCRCKWMk2H_zuS4JeDFTvyZH1skJYF_TET1DrCZHMPicw-Yk3_m2P-ilC-yidPPoVzeU8Jj3tQ6gtX3975qiQW7pt2qbgjKAuq2wsz_9hxLBtMB5rQPafFoxop7O4BklvZ9-ECcK6dfI2CAx9_tjQ"}]}', $response->getContent());
        self::assertEquals('application/jwk-set+json; charset=UTF-8', $response->headers->get('Content-Type'));
        self::assertEquals('max-age=100, must-revalidate, no-transform, public', $response->headers->get('Cache-Control'));
    }

    public function testJWKSetRouteFromExternalBundleIsAvailable()
    {
        $client = static::createClient();

        $container = $client->getContainer();
        self::assertTrue($container->has('jose.key_set.jwkset2'));
        self::assertInstanceOf(JWKSet::class, $container->get('jose.key_set.jwkset2'));

        $client->request('GET', '/keys/2.jwkset');
        /** @var Response $response */
        $response = $client->getResponse();
        self::assertInstanceOf(Response::class, $response);

        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('{"keys":[{"kty":"oct","k":"dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g"},{"kty":"oct","k":"bwIAv5Nn-fo8p4LCEvM4IR9eLXgzJRs8jXCLb3xR0tDJGiZ46KheO4ip6htFKyN2aqJqlNi9-7hB6I1aLLy1IRT9-vcBoCSGu977cNAUuRLkRp7vo8s6MsxhB8WvQBDRZghV7jIYaune-3vbE7iDU2AESr8BUtorckLoO9uW__fIabaa3hJMMQIHCzYQbJKZvlCRCKWMk2H_zuS4JeDFTvyZH1skJYF_TET1DrCZHMPicw-Yk3_m2P-ilC-yidPPoVzeU8Jj3tQ6gtX3975qiQW7pt2qbgjKAuq2wsz_9hxLBtMB5rQPafFoxop7O4BklvZ9-ECcK6dfI2CAx9_tjQ"}]}', $response->getContent());
        self::assertEquals('application/jwk-set+json; charset=UTF-8', $response->headers->get('Content-Type'));
        self::assertEquals('max-age=3600, must-revalidate, no-transform, public', $response->headers->get('Cache-Control'));
    }
}

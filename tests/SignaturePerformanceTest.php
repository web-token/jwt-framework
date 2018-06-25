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

namespace Jose\Tests;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;
use Blackfire\Bridge\PhpUnit\TestCaseTrait;
use Blackfire\Profile;

/**
 * @group Performance
 */
class JWSTest extends TestCase
{
    use TestCaseTrait;

    /**
     * @test
     * @requires extension blackfire
     */
    public function iCreateASignedToken()
    {
        $jsonConverter = new StandardConverter();
        $jwsBuilder = new JWSBuilder(
            $jsonConverter,
            AlgorithmManager::create([
                new None(),
            ])
        );
        $serializer = new CompactSerializer($jsonConverter);

        $claims = [
            'nbf' => \time(),
            'iat' => \time(),
            'exp' => \time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $payload = $jsonConverter->encode($claims);
        $header = ['alg' => 'none'];
        $jwk = JWK::create([
            'kty' => 'none',
            'use' => 'sig',
            'alg' => 'none',
        ]);

        $config = new Profile\Configuration();
        $config
            ->assert('main.peak_memory < 10mb', 'Peak Memory')
        ;

        $profile = $this->assertBlackfire($config, function () use ($jwsBuilder, $serializer, $payload, $header, $jwk) {
            $jws = $jwsBuilder
                ->create()
                ->withPayload($payload)
                ->addSignature($jwk, $header)
                ->build()
            ;
            $serializer->serialize($jws, 0);
        });
    }
}

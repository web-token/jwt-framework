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

namespace Jose\Bundle\JoseFramework\Tests\Functional\Signature;

use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class JWSComputationTest extends WebTestCase
{
    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        if (!class_exists(JWSBuilderFactory::class)) {
            $this->markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
    }

    public function testCreateAndLoadAToken()
    {
        $client = static::createClient();
        $container = $client->getContainer();

        $jwk = JWK::create([
            'kty' => 'oct',
            'k'   => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);

        /** @var JWSBuilder $builder */
        $builder = $container->get('jose.jws_builder.builder1');

        /** @var JWSVerifier $loader */
        $loader = $container->get('jose.jws_verifier.loader1');

        $serializer = new CompactSerializer(new StandardConverter());

        $jws = $builder
            ->create()
            ->withPayload('Hello World!')
            ->addSignature($jwk, [
                'alg' => 'HS256',
            ])
            ->build();
        $token = $serializer->serialize($jws, 0);

        $loaded = $serializer->unserialize($token);
        self::assertTrue($loader->verifyWithKey($loaded, $jwk, 0));
    }
}

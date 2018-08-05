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

namespace Jose\Component\Signature\Tests;

use Base64Url\Base64Url;
use Jose\Component\Signature\JWS;

/**
 * @group JWS
 * @group Unit
 */
class JWSTest extends SignatureTest
{
    /**
     * @test
     */
    public function jWS()
    {
        $claims = [
            'nbf' => \time(),
            'iat' => \time(),
            'exp' => \time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = ['alg' => 'none'];
        $jws = JWS::create(\json_encode($claims), \json_encode($claims))
            ->addSignature('', $header, Base64Url::encode(\json_encode($header)));

        static::assertEquals(\json_encode($claims), $jws->getPayload());
        static::assertEquals(1, $jws->countSignatures());
        static::assertTrue($jws->getSignature(0)->hasProtectedHeaderParameter('alg'));
        static::assertEquals($header, $jws->getSignature(0)->getProtectedHeader());
        static::assertEquals('none', $jws->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertEquals([], $jws->getSignature(0)->getHeader());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The signature does not exist.
     *
     * @test
     */
    public function toCompactJSONFailed()
    {
        $claims = [
            'nbf' => \time(),
            'iat' => \time(),
            'exp' => \time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = JWS::create(\json_encode($claims), \json_encode($claims));
        $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The signature does not exist.
     *
     * @test
     */
    public function toFlattenedJSONFailed()
    {
        $claims = [
            'nbf' => \time(),
            'iat' => \time(),
            'exp' => \time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = JWS::create(\json_encode($claims), \json_encode($claims));
        $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 0);
    }

    /**
     * @expectedException \LogicException
     * @expectedExceptionMessage No signature.
     *
     * @test
     */
    public function toJSONFailed()
    {
        $claims = [
            'nbf' => \time(),
            'iat' => \time(),
            'exp' => \time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = JWS::create(\json_encode($claims), \json_encode($claims));
        $this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0);
    }

    /**
     * @expectedException \LogicException
     * @expectedExceptionMessage The signature contains unprotected header parameters and cannot be converted into compact JSON
     *
     * @test
     */
    public function signatureContainsUnprotectedHeader()
    {
        $claims = [
            'nbf' => \time(),
            'iat' => \time(),
            'exp' => \time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = ['alg' => 'none'];
        $jws = JWS::create(\json_encode($claims), \json_encode($claims))
            ->addSignature('', $header, Base64Url::encode(\json_encode($header)), ['foo' => 'bar']);

        $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header "foo" does not exist
     *
     * @test
     */
    public function signatureDoesNotContainHeader()
    {
        $claims = [
            'nbf' => \time(),
            'iat' => \time(),
            'exp' => \time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = ['alg' => 'none'];
        $jws = JWS::create(\json_encode($claims), \json_encode($claims))
            ->addSignature('', $header, Base64Url::encode(\json_encode($header)));
        $jws->getSignature(0)->getHeaderParameter('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The protected header "foo" does not exist
     *
     * @test
     */
    public function signatureDoesNotContainProtectedHeader()
    {
        $claims = [
            'nbf' => \time(),
            'iat' => \time(),
            'exp' => \time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = ['alg' => 'none'];
        $jws = JWS::create(\json_encode($claims), \json_encode($claims))
            ->addSignature('', $header, Base64Url::encode(\json_encode($header)));
        $jws->getSignature(0)->getProtectedHeaderParameter('foo');
    }
}

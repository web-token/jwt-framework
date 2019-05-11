<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Tests;

use Base64Url\Base64Url;
use Jose\Component\Signature\JWS;

/**
 * @group JWS
 * @group unit
 *
 * @internal
 * @coversNothing
 */
class JWSTest extends SignatureTest
{
    /**
     * @test
     */
    public function jWS()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = ['alg' => 'none'];
        $jws = new JWS(json_encode($claims), json_encode($claims));
        $jws = $jws->addSignature('', $header, Base64Url::encode(json_encode($header)));

        static::assertEquals(json_encode($claims), $jws->getPayload());
        static::assertEquals(1, $jws->countSignatures());
        static::assertTrue($jws->getSignature(0)->hasProtectedHeaderParameter('alg'));
        static::assertEquals($header, $jws->getSignature(0)->getProtectedHeader());
        static::assertEquals('none', $jws->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertEquals([], $jws->getSignature(0)->getHeader());
    }

    /**
     * @test
     */
    public function toCompactJSONFailed()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The signature does not exist.');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = new JWS(json_encode($claims), json_encode($claims));
        $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
    }

    /**
     * @test
     */
    public function toFlattenedJSONFailed()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The signature does not exist.');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = new JWS(json_encode($claims), json_encode($claims));
        $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 0);
    }

    /**
     * @test
     */
    public function toJSONFailed()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('No signature.');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = new JWS(json_encode($claims), json_encode($claims));
        $this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0);
    }

    /**
     * @test
     */
    public function signatureContainsUnprotectedHeader()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The signature contains unprotected header parameters and cannot be converted into compact JSON');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = ['alg' => 'none'];
        $jws = new JWS(json_encode($claims), json_encode($claims));
        $jws = $jws->addSignature('', $header, Base64Url::encode(json_encode($header)), ['foo' => 'bar']);

        $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
    }

    /**
     * @test
     */
    public function signatureDoesNotContainHeader()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The header "foo" does not exist');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = ['alg' => 'none'];
        $jws = new JWS(json_encode($claims), json_encode($claims));
        $jws = $jws->addSignature('', $header, Base64Url::encode(json_encode($header)));
        $jws->getSignature(0)->getHeaderParameter('foo');
    }

    /**
     * @test
     */
    public function signatureDoesNotContainProtectedHeader()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The protected header "foo" does not exist');

        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $header = ['alg' => 'none'];
        $jws = new JWS(json_encode($claims), json_encode($claims));
        $jws = $jws->addSignature('', $header, Base64Url::encode(json_encode($header)));
        $jws->getSignature(0)->getProtectedHeaderParameter('foo');
    }
}

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

namespace Jose\Tests\Component\Signature;

use Base64Url\Base64Url;
use InvalidArgumentException;
use Jose\Component\Signature\JWS;
use LogicException;

/**
 * @group JWS
 * @group unit
 *
 * @internal
 */
class JWSTest extends SignatureTest
{
    /**
     * @test
     */
    public function jWS(): void
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
    public function toCompactJSONFailed(): void
    {
        $this->expectException(InvalidArgumentException::class);
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
    public function toFlattenedJSONFailed(): void
    {
        $this->expectException(InvalidArgumentException::class);
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
    public function toJSONFailed(): void
    {
        $this->expectException(LogicException::class);
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
    public function signatureContainsUnprotectedHeader(): void
    {
        $this->expectException(LogicException::class);
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
    public function signatureDoesNotContainHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
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
    public function signatureDoesNotContainProtectedHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
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

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

namespace Jose\Tests\Easy;

use Exception;
use InvalidArgumentException;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS1;
use Jose\Easy\Build;
use Jose\Easy\Load;
use PHPUnit\Framework\TestCase;

/**
 * @group easy
 *
 * @covers \Jose\Easy\Build
 * @covers \Jose\Easy\JWSBuilder
 * @covers \Jose\Easy\JWT
 * @covers \Jose\Easy\Validate
 *
 * @internal
 */
class SignatureTest extends TestCase
{
    /**
     * @test
     */
    public function jwsCanBeCreated(): void
    {
        $time = time();
        $jws = Build::jws()
            ->exp($time + 3600)
            ->iat($time)
            ->nbf($time)
            ->jti('0123456789', true)
            ->alg('RS512')
            ->iss('issuer')
            ->aud('audience1')
            ->aud('audience2')
            ->sub('subject')
            ->claim('is_root', true)
            ->claim('roles', ['ROLE1' => true, 'ROLE2' => 0.007])
            ->crit(['alg'])
            ->sign($this->rsaKey())
        ;

        $jwt = Load::jws($jws)
            ->algs(['RS256', 'RS512'])
            ->exp()
            ->iat()
            ->nbf()
            ->aud('audience1')
            ->iss('issuer')
            ->sub('subject')
            ->jti('0123456789')
            ->key($this->rsaKey())
            ->run()
        ;

        static::assertEquals($time, $jwt->claims->iat());
        static::assertEquals($time, $jwt->claims->nbf());
        static::assertEquals($time + 3600, $jwt->claims->exp());
        static::assertEquals('0123456789', $jwt->claims->jti());
        static::assertEquals('issuer', $jwt->claims->iss());
        static::assertEquals('subject', $jwt->claims->sub());
        static::assertEquals(['audience1', 'audience2'], $jwt->claims->aud());
        static::assertEquals(true, $jwt->claims->is_root());
        static::assertEquals(['ROLE1' => true, 'ROLE2' => 0.007], $jwt->claims->roles());

        static::assertEquals(['jti' => '0123456789', 'alg' => 'RS512', 'crit' => ['alg']], $jwt->header->all());
        static::assertEquals('RS512', $jwt->header->alg());
        static::assertEquals('0123456789', $jwt->header->jti());
    }

    /**
     * @test
     */
    public function invalidSignatureRejectsTheToken(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid signature');
        $time = time();
        $jws = Build::jws()
            ->exp($time + 3600)
            ->iat($time)
            ->nbf($time)
            ->jti('0123456789', true)
            ->alg('HS256')
            ->iss('issuer')
            ->aud('audience1')
            ->aud('audience2')
            ->sub('subject')
            ->claim('is_root', true)
            ->claim('roles', ['ROLE1' => true, 'ROLE2' => 0.007])
            ->crit(['alg'])
            ->sign(new JWK(['kty' => 'oct', 'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo']))
        ;

        Load::jws($jws)
            ->algs(['HS256'])
            ->exp()
            ->iat()
            ->nbf()
            ->aud('audience1')
            ->iss('issuer')
            ->sub('subject')
            ->jti('0123456789')
            ->key(new JWK(['kty' => 'oct', 'k' => 'BARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBAR']))
            ->run()
        ;
    }

    /**
     * @test
     */
    public function algorithmIsNotAllowed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm "none" is not supported.');
        $time = time();
        $jws = Build::jws()
            ->exp($time + 3600)
            ->iat($time)
            ->nbf($time)
            ->jti('0123456789', true)
            ->alg('none')
            ->iss('issuer')
            ->aud('audience1')
            ->aud('audience2')
            ->sub('subject')
            ->claim('is_root', true)
            ->claim('roles', ['ROLE1' => true, 'ROLE2' => 0.007])
            ->crit(['alg'])
            ->sign($this->noneKey())
        ;

        Load::jws($jws)
            ->algs(['HS256'])
            ->exp()
            ->iat()
            ->nbf()
            ->aud('audience1')
            ->iss('issuer')
            ->sub('subject')
            ->jti('0123456789')
            ->key(new JWK(['kty' => 'oct', 'k' => 'BARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBARBAR']))
            ->run()
        ;
    }

    /**
     * @test
     */
    public function tokenExpired(): void
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The token expired.');
        $time = time();
        $jws = Build::jws()
            ->exp($time - 1)
            ->iat($time)
            ->nbf($time)
            ->jti('0123456789', true)
            ->alg('RS256')
            ->iss('issuer')
            ->aud('audience1')
            ->aud('audience2')
            ->sub('subject')
            ->claim('is_root', true)
            ->claim('roles', ['ROLE1' => true, 'ROLE2' => 0.007])
            ->crit(['alg'])
            ->sign($this->rsaKey())
        ;

        Load::jws($jws)
            ->algs(['RS256'])
            ->exp()
            ->iat()
            ->nbf()
            ->aud('audience1')
            ->iss('issuer')
            ->sub('subject')
            ->jti('0123456789')
            ->key($this->rsaKey())
            ->run()
        ;
    }

    /**
     * @test
     */
    public function jwsCanBeCreatedWithCustomAlgorithm(): void
    {
        $time = time();
        $jws = Build::jws()
            ->exp($time + 3600)
            ->iat($time)
            ->nbf($time)
            ->jti('0123456789')
            ->alg(new HS1())
            ->sign($this->octKey())
        ;

        $jwt = Load::jws($jws)
            ->algs(['RS256', new HS1()])
            ->exp()
            ->iat()
            ->nbf()
            ->aud('audience1')
            ->iss('issuer')
            ->sub('subject')
            ->jti('0123456789')
            ->key($this->octKey())
            ->run()
        ;

        static::assertEquals($time, $jwt->claims->iat());
        static::assertEquals($time, $jwt->claims->nbf());
        static::assertEquals($time + 3600, $jwt->claims->exp());
        static::assertEquals('0123456789', $jwt->claims->jti());

        static::assertEquals('HS1', $jwt->header->alg());
    }

    private function rsaKey(): JWK
    {
        return new JWK([
            'kty' => 'RSA',
            'kid' => 'bilbo.baggins@hobbiton.example',
            'use' => 'sig',
            'n' => 'n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw',
            'e' => 'AQAB',
            'd' => 'bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ',
            'p' => '3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k',
            'q' => 'uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc',
            'dp' => 'B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik',
            'dq' => 'CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8',
            'qi' => '3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4',
        ]);
    }

    private function octKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo',
        ]);
    }

    private function noneKey(): JWK
    {
        return new JWK([
            'kty' => 'none',
        ]);
    }
}

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

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CCM_16_128;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP512;
use Jose\Easy\Build;
use Jose\Easy\Load;
use PHPUnit\Framework\TestCase;

/**
 * @group easy
 *
 * @internal
 * @covers \Jose\Easy\Build
 * @covers \Jose\Easy\JWEBuilder
 * @covers \Jose\Easy\JWT
 */
class EncryptionTest extends TestCase
{
    /**
     * @test
     */
    public function jweCanBeCreated(): void
    {
        $time = time();
        $jwe = Build::jwe()
            ->exp($time + 3600)
            ->iat($time)
            ->nbf($time)
            ->jti('0123456789', true)
            ->iss('issuer')
            ->aud('audience1')
            ->aud('audience2')
            ->sub('subject')
            ->alg('RSA-OAEP-256')
            ->enc('A256GCM')
            ->zip('DEF')
            ->claim('is_root', true)
            ->claim('roles', ['ROLE1' => true, 'ROLE2' => 0.007])
            ->crit(['alg', 'enc'])
            ->encrypt($this->rsaKey())
        ;

        $jwt = Load::jwe($jwe)
            ->algs(['RSA-OAEP', 'RSA-OAEP-256'])
            ->encs(['A128GCM', 'A256GCM'])
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

        static::assertEquals(['jti' => '0123456789', 'alg' => 'RSA-OAEP-256', 'enc' => 'A256GCM', 'crit' => ['alg', 'enc'], 'zip' => 'DEF'], $jwt->header->all());
        static::assertEquals('RSA-OAEP-256', $jwt->header->alg());
        static::assertEquals('A256GCM', $jwt->header->enc());
        static::assertEquals('0123456789', $jwt->header->jti());
    }

    /**
     * @test
     */
    public function jweCanBeCreatedWithCustomAlgorithm(): void
    {
        $time = time();
        $jwe = Build::jwe()
            ->exp($time + 3600)
            ->iat($time)
            ->nbf($time)
            ->jti('0123456789')
            ->alg(new RSAOAEP512())
            ->enc(new A256CCM_16_128())
            ->encrypt($this->rsaKey())
        ;

        $jwt = Load::jwe($jwe)
            ->algs(['RSA-OAEP', new RSAOAEP512()])
            ->encs(['A128GCM', new A256CCM_16_128()])
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

        static::assertEquals('RSA-OAEP-512', $jwt->header->alg());
        static::assertEquals('A256CCM-16-128', $jwt->header->enc());
    }

    private function rsaKey(): JWK
    {
        return new JWK([
            'kty' => 'RSA',
            'kid' => 'bilbo.baggins@hobbiton.example',
            'use' => 'enc',
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
}

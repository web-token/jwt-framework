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

namespace Jose\Component\Core\Util;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

/**
 * @internal
 */
class ECKey
{
    public static function convertToPEM(JWK $jwk): string
    {
        if ($jwk->has('d')) {
            return self::convertPrivateKeyToPEM($jwk);
        } else {
            return self::convertPublicKeyToPEM($jwk);
        }
    }

    public static function convertPublicKeyToPEM(JWK $jwk): string
    {
        switch ($jwk->get('crv')) {
            case 'P-256':
                $der = self::p256PublicKey();

                break;
            case 'P-384':
                $der = self::p384PublicKey();

                break;
            case 'P-521':
                $der = self::p521PublicKey();

                break;
            default:
                throw new \InvalidArgumentException('Unsupported curve.');
        }
        $der .= self::getKey($jwk);
        $pem = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $pem .= \chunk_split(\base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END PUBLIC KEY-----'.PHP_EOL;

        return $pem;
    }

    public static function convertPrivateKeyToPEM(JWK $jwk): string
    {
        switch ($jwk->get('crv')) {
            case 'P-256':
                $der = self::p256PrivateKey($jwk);

                break;
            case 'P-384':
                $der = self::p384PrivateKey($jwk);

                break;
            case 'P-521':
                $der = self::p521PrivateKey($jwk);

                break;
            default:
                throw new \InvalidArgumentException('Unsupported curve.');
        }
        $der .= self::getKey($jwk);
        $pem = '-----BEGIN EC PRIVATE KEY-----'.PHP_EOL;
        $pem .= \chunk_split(\base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END EC PRIVATE KEY-----'.PHP_EOL;

        return $pem;
    }

    private static function p256PublicKey(): string
    {
        return \pack('H*',
            '3059' // SEQUENCE, length 89
                .'3013' // SEQUENCE, length 19
                    .'0607' // OID, length 7
                        .'2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
                    .'0608' // OID, length 8
                        .'2a8648ce3d030107' // 1.2.840.10045.3.1.7 = P-256 Curve
                .'0342' // BIT STRING, length 66
                    .'00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p384PublicKey(): string
    {
        return \pack('H*',
            '3076' // SEQUENCE, length 118
                .'3010' // SEQUENCE, length 16
                    .'0607' // OID, length 7
                        .'2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
                    .'0605' // OID, length 5
                        .'2b81040022' // 1.3.132.0.34 = P-384 Curve
                .'0362' // BIT STRING, length 98
                    .'00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p521PublicKey(): string
    {
        return \pack('H*',
            '30819b' // SEQUENCE, length 154
                .'3010' // SEQUENCE, length 16
                    .'0607' // OID, length 7
                        .'2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
                    .'0605' // OID, length 5
                        .'2b81040023' // 1.3.132.0.35 = P-521 Curve
                .'038186' // BIT STRING, length 134
                    .'00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p256PrivateKey(JWK $jwk): string
    {
        $d = \unpack('H*', Base64Url::decode($jwk->get('d')))[1];
        $dl = \mb_strlen($d, '8bit') / 2;

        return \pack('H*',
            '30'.\dechex(87 + $dl) // SEQUENCE, length 87+length($d)
                .'020101' // INTEGER, 1
                .'04'.\dechex($dl)   // OCTET STRING, length($d)
                    .$d
                .'a00a' // TAGGED OBJECT #0, length 10
                    .'0608' // OID, length 8
                        .'2a8648ce3d030107' // 1.3.132.0.34 = P-384 Curve
                .'a144' //  TAGGED OBJECT #1, length 68
                    .'0342' // BIT STRING, length 66
                    .'00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p384PrivateKey(JWK $jwk): string
    {
        $d = \unpack('H*', Base64Url::decode($jwk->get('d')))[1];
        $dl = \mb_strlen($d, '8bit') / 2;

        return \pack('H*',
            '3081'.\dechex(116 + $dl) // SEQUENCE, length 116 + length($d)
                .'020101' // INTEGER, 1
                .'04'.\dechex($dl)   // OCTET STRING, length($d)
                    .$d
                .'a007' // TAGGED OBJECT #0, length 7
                    .'0605' // OID, length 5
                        .'2b81040022' // 1.3.132.0.34 = P-384 Curve
                .'a164' //  TAGGED OBJECT #1, length 100
                    .'0362' // BIT STRING, length 98
                    .'00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p521PrivateKey(JWK $jwk): string
    {
        $d = \unpack('H*', Base64Url::decode($jwk->get('d')))[1];
        $dl = \mb_strlen($d, '8bit') / 2;

        return \pack('H*',
            '3081'.\dechex(154 + $dl) // SEQUENCE, length 154+length(d)
                .'020101' // INTEGER, 1
                .'04'.\dechex($dl)   // OCTET STRING, length(d)
                    .$d
                .'a007' // TAGGED OBJECT #0, length 7
                    .'0605' // OID, length 5
                        .'2b81040023' // 1.3.132.0.35 = P-521 Curve
                .'a18189' //  TAGGED OBJECT #1, length 137
                    .'038186' // BIT STRING, length 134
                    .'00' // prepend with NUL - pubkey will follow
        );
    }

    private static function getKey(JWK $jwk): string
    {
        return
            \pack('H*', '04')
            .Base64Url::decode($jwk->get('x'))
            .Base64Url::decode($jwk->get('y'));
    }
}

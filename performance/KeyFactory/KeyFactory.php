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

namespace Jose\Performance\KeyFactory;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Ecc\NistCurve;

/**
 * @Revs(1000)
 * @Groups({"KeyFactory"})
 */
final class KeyFactory
{
    /**
     * @Subject
     */
    public function usingThePurePhpMethod()
    {
        $curve = NistCurve::curve256();
        $privateKey = $curve->createPrivateKey();
        $publicKey = $curve->createPublicKey($privateKey);

        new JWK([
            'kty' => 'EC',
            'crv' => $curve,
            'd' => Base64Url::encode(\gmp_export($privateKey->getSecret())),
            'x' => Base64Url::encode(\gmp_export($publicKey->getPoint()->getX())),
            'y' => Base64Url::encode(\gmp_export($publicKey->getPoint()->getY())),
        ]);
    }

    /**
     * @Subject
     */
    public function usingOpenSSL()
    {
        $key = \openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $res = \openssl_pkey_export($key, $out);
        if (false === $res) {
            throw new \RuntimeException('Unable to create the key');
        }
        $res = \openssl_pkey_get_private($out);

        $details = \openssl_pkey_get_details($res);

        new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => Base64Url::encode($details['ec']['x']),
            'y' => Base64Url::encode($details['ec']['y']),
            'd' => Base64Url::encode($details['ec']['d']),
        ]);
    }
}

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
use Jose\Component\KeyManagement\JWKFactory;

/**
 * @Revs(100)
 * @Groups({"KeyFactory"})
 */
final class KeyFactory
{
    /**
     * @Subject()
     */
    public function usingTheFactoryMethod()
    {
        JWKFactory::createECKey('P-256');
    }

    /**
     * @Subject()
     */
    public function usingOpenSSL()
    {
        $key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $res = openssl_pkey_export($key, $out);
        if (false === $res) {
            throw new \RuntimeException('Unable to create the key');
        }
        $res = openssl_pkey_get_private($out);

        $details = openssl_pkey_get_details($res);

        $jwk = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x'   => Base64Url::encode(bin2hex($details['ec']['x'])),
            'y'   => Base64Url::encode(bin2hex($details['ec']['y'])),
            'd'   => Base64Url::encode(bin2hex($details['ec']['d'])),
        ]);
    }
}

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Ecc\NistCurve;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;
use Jose\Component\KeyManagement\KeyConverter\RSAKey;

/**
 * Class JWKFactory.
 */
final class JWKFactory
{
    /**
     * @param int   $size   The key size in bits
     * @param array $values values to configure the key
     *
     * @return JWK
     */
    public static function createRSAKey(int $size, array $values = []): JWK
    {
        if (0 !== $size % 8) {
            throw new \InvalidArgumentException('Invalid key size.');
        }

        if (384 > $size) {
            throw new \InvalidArgumentException('Key length is too short. It needs to be at least 384 bits.');
        }

        $key = openssl_pkey_new([
            'private_key_bits' => $size,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $out);
        $rsa = RSAKey::createFromPEM($out);
        $values = array_merge(
            $values,
            $rsa->toArray()
        );

        return JWK::create($values);
    }

    /**
     * @param string $curve  The curve
     * @param array  $values values to configure the key
     *
     * @return JWK
     */
    public static function createECKey(string $curve, array $values = []): JWK
    {
        switch ($curve) {
            case 'P-256':
                $nistCurve = NistCurve::curve256();

                break;
            case 'P-384':
                $nistCurve = NistCurve::curve384();

                break;
            case 'P-521':
                $nistCurve = NistCurve::curve521();

                break;
            default:
                throw new \InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve));
        }

        $privateKey = $nistCurve->createPrivateKey();
        $publicKey = $nistCurve->createPublicKey($privateKey);

        $values = array_merge(
            $values,
            [
                'kty' => 'EC',
                'crv' => $curve,
                'd' => Base64Url::encode(gmp_export($privateKey->getSecret())),
                'x' => Base64Url::encode(gmp_export($publicKey->getPoint()->getX())),
                'y' => Base64Url::encode(gmp_export($publicKey->getPoint()->getY())),
            ]
        );

        return JWK::create($values);
    }

    /**
     * @param int   $size   The key size in bits
     * @param array $values values to configure the key
     *
     * @return JWK
     */
    public static function createOctKey(int $size, array $values = []): JWK
    {
        if (0 !== $size % 8) {
            throw new \InvalidArgumentException('Invalid key size.');
        }
        $values = array_merge(
            $values,
            [
                'kty' => 'oct',
                'k' => Base64Url::encode(random_bytes($size / 8)),
            ]
        );

        return JWK::create($values);
    }

    /**
     * @param string $curve  The curve
     * @param array  $values values to configure the key
     *
     * @return JWK
     */
    public static function createOKPKey(string $curve, array $values = []): JWK
    {
        switch ($curve) {
            case 'X25519':
                $d = sodium_randombytes_buf(\Sodium\CRYPTO_BOX_SEEDBYTES);
                $x = sodium_crypto_scalarmult_base($d);

                break;
            case 'Ed25519':
                $d = sodium_randombytes_buf(\Sodium\CRYPTO_SIGN_SEEDBYTES);
                $keyPair = sodium_crypto_sign_seed_keypair($d);
                $x = sodium_crypto_sign_publickey($keyPair);

                break;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported "%s" curve', $curve));
        }

        $values = array_merge(
            $values,
            [
                'kty' => 'OKP',
                'crv' => $curve,
                'x' => Base64Url::encode($x),
                'd' => Base64Url::encode($d),
            ]
        );

        return JWK::create($values);
    }

    /**
     * @param array $values values to configure the key
     *
     * @return JWK
     */
    public static function createNoneKey(array $values = []): JWK
    {
        $values = array_merge(
            $values,
            [
                'kty' => 'none',
                'alg' => 'none',
                'use' => 'sig',
            ]
        );

        return JWK::create($values);
    }

    /**
     * @param string $value
     *
     * @return JWK|JWKSet
     */
    public static function createFromString(string $value)
    {
        $json = json_decode($value, true);
        if (!is_array($json)) {
            throw new \InvalidArgumentException('Invalid key or key set.');
        }

        return self::createFromValues($json);
    }

    /**
     * @param array $values
     *
     * @return JWK|JWKSet
     */
    public static function createFromValues(array $values)
    {
        if (array_key_exists('keys', $values) && is_array($values['keys'])) {
            return JWKSet::createFromKeyData($values);
        }

        return JWK::create($values);
    }

    /**
     * @param string $file
     * @param array  $additional_values
     *
     * @return JWK
     */
    public static function createFromCertificateFile(string $file, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadKeyFromCertificateFile($file);
        $values = array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * @param string      $file
     * @param null|string $secret
     * @param array       $additional_values
     *
     * @return JWK
     */
    public static function createFromPKCS12CertificateFile(string $file, ?string $secret = '', array $additional_values = []): JWK
    {
        $res = openssl_pkcs12_read(file_get_contents($file), $certs, $secret);
        if (false === $res || !is_array($certs) || !array_key_exists('pkey', $certs)) {
            throw new \RuntimeException('Unable to load the certificates.');
        }

        return self::createFromKey($certs['pkey'], null, $additional_values);
    }

    /**
     * @param string $certificate
     * @param array  $additional_values
     *
     * @return JWK
     */
    public static function createFromCertificate(string $certificate, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadKeyFromCertificate($certificate);
        $values = array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * @param resource $res
     * @param array    $additional_values
     *
     * @return JWK
     */
    public static function createFromX509Resource($res, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadKeyFromX509Resource($res);
        $values = array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * @param string      $file
     * @param null|string $password
     * @param array       $additional_values
     *
     * @return JWK
     */
    public static function createFromKeyFile(string $file, ?string $password = null, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadFromKeyFile($file, $password);
        $values = array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * @param string      $key
     * @param null|string $password
     * @param array       $additional_values
     *
     * @return JWK
     */
    public static function createFromKey(string $key, ?string $password = null, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadFromKey($key, $password);
        $values = array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * @param array $x5c
     * @param array $additional_values
     *
     * @return JWK
     */
    public static function createFromX5C(array $x5c, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadFromX5C($x5c);
        $values = array_merge($values, $additional_values);

        return JWK::create($values);
    }
}

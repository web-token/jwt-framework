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

namespace Jose\Component\KeyManagement;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Ecc\NistCurve;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;
use Jose\Component\KeyManagement\KeyConverter\RSAKey;

class JWKFactory
{
    /**
     * Creates a RSA key with the given key size and additional values.
     *
     * @param int   $size   The key size in bits
     * @param array $values values to configure the key
     */
    public static function createRSAKey(int $size, array $values = []): JWK
    {
        if (0 !== $size % 8) {
            throw new \InvalidArgumentException('Invalid key size.');
        }

        if (384 > $size) {
            throw new \InvalidArgumentException('Key length is too short. It needs to be at least 384 bits.');
        }

        $key = \openssl_pkey_new([
            'private_key_bits' => $size,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        \openssl_pkey_export($key, $out);
        $rsa = RSAKey::createFromPEM($out);
        $values = \array_merge(
            $values,
            $rsa->toArray()
        );

        return JWK::create($values);
    }

    /**
     * Creates a EC key with the given curve and additional values.
     *
     * @param string $curve  The curve
     * @param array  $values values to configure the key
     */
    public static function createECKey(string $curve, array $values = []): JWK
    {
        try {
            $jwk = self::createECKeyUsingOpenSSL($curve);
        } catch (\Exception $e) {
            $jwk = self::createECKeyUsingPurePhp($curve);
        }
        $values = \array_merge($values, $jwk);

        return JWK::create($values);
    }

    private static function createECKeyUsingPurePhp(string $curve): array
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
                throw new \InvalidArgumentException(\sprintf('The curve "%s" is not supported.', $curve));
        }

        $privateKey = $nistCurve->createPrivateKey();
        $publicKey = $nistCurve->createPublicKey($privateKey);

        return [
            'kty' => 'EC',
            'crv' => $curve,
            'd' => Base64Url::encode(\gmp_export($privateKey->getSecret())),
            'x' => Base64Url::encode(\gmp_export($publicKey->getPoint()->getX())),
            'y' => Base64Url::encode(\gmp_export($publicKey->getPoint()->getY())),
        ];
    }

    private static function createECKeyUsingOpenSSL(string $curve): array
    {
        $key = \openssl_pkey_new([
            'curve_name' => self::getOpensslCurveName($curve),
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $res = \openssl_pkey_export($key, $out);
        if (false === $res) {
            throw new \RuntimeException('Unable to create the key');
        }
        $res = \openssl_pkey_get_private($out);

        $details = \openssl_pkey_get_details($res);

        return [
            'kty' => 'EC',
            'crv' => $curve,
            'x' => Base64Url::encode(\bin2hex($details['ec']['x'])),
            'y' => Base64Url::encode(\bin2hex($details['ec']['y'])),
            'd' => Base64Url::encode(\bin2hex($details['ec']['d'])),
        ];
    }

    private static function getOpensslCurveName(string $curve): string
    {
        switch ($curve) {
            case 'P-256':
                return 'prime256v1';
            case 'P-384':
                return 'secp384r1';
            case 'P-521':
                return 'secp521r1';
            default:
                throw new \InvalidArgumentException(\sprintf('The curve "%s" is not supported.', $curve));
        }
    }

    /**
     * Creates a octet key with the given key size and additional values.
     *
     * @param int   $size   The key size in bits
     * @param array $values values to configure the key
     */
    public static function createOctKey(int $size, array $values = []): JWK
    {
        if (0 !== $size % 8) {
            throw new \InvalidArgumentException('Invalid key size.');
        }
        $values = \array_merge(
            $values,
            [
                'kty' => 'oct',
                'k' => Base64Url::encode(\random_bytes($size / 8)),
            ]
        );

        return JWK::create($values);
    }

    /**
     * Creates a OKP key with the given curve and additional values.
     *
     * @param string $curve  The curve
     * @param array  $values values to configure the key
     */
    public static function createOKPKey(string $curve, array $values = []): JWK
    {
        switch ($curve) {
            case 'X25519':
                $keyPair = \sodium_crypto_box_keypair();
                $d = \sodium_crypto_box_secretkey($keyPair);
                $x = \sodium_crypto_box_publickey($keyPair);

                break;
            case 'Ed25519':
                $keyPair = \sodium_crypto_sign_keypair();
                $d = \sodium_crypto_sign_secretkey($keyPair);
                $x = \sodium_crypto_sign_publickey($keyPair);

                break;
            default:
                throw new \InvalidArgumentException(\sprintf('Unsupported "%s" curve', $curve));
        }

        $values = \array_merge(
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
     * Creates a none key with the given additional values.
     * Please note that this key type is not pat of any specification.
     * It is used to prevent the use of the "none" algorithm with other key types.
     *
     * @param array $values values to configure the key
     */
    public static function createNoneKey(array $values = []): JWK
    {
        $values = \array_merge(
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
     * Creates a key from a Json string.
     *
     * @return JWK|JWKSet
     */
    public static function createFromJsonObject(string $value)
    {
        $json = \json_decode($value, true);
        if (!\is_array($json)) {
            throw new \InvalidArgumentException('Invalid key or key set.');
        }

        return self::createFromValues($json);
    }

    /**
     * Creates a key or key set from the given input.
     *
     * @return JWK|JWKSet
     */
    public static function createFromValues(array $values)
    {
        if (\array_key_exists('keys', $values) && \is_array($values['keys'])) {
            return JWKSet::createFromKeyData($values);
        }

        return JWK::create($values);
    }

    /**
     * This method create a JWK object using a shared secret.
     */
    public static function createFromSecret(string $secret, array $additional_values = []): JWK
    {
        $values = \array_merge(
            $additional_values,
            [
                'kty' => 'oct',
                'k' => Base64Url::encode($secret),
            ]
        );

        return JWK::create($values);
    }

    /**
     * This method will try to load a X.509 certificate and convert it into a public key.
     */
    public static function createFromCertificateFile(string $file, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadKeyFromCertificateFile($file);
        $values = \array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * Extract a keyfrom a key set identified by the given index .
     *
     * @param int|string $index
     */
    public static function createFromKeySet(JWKSet $jwkset, $index): JWK
    {
        return $jwkset->get($index);
    }

    /**
     * This method will try to load a PKCS#12 file and convert it into a public key.
     *
     * @throws \Exception
     */
    public static function createFromPKCS12CertificateFile(string $file, ?string $secret = '', array $additional_values = []): JWK
    {
        $res = \openssl_pkcs12_read(\file_get_contents($file), $certs, $secret);
        if (false === $res || !\is_array($certs) || !\array_key_exists('pkey', $certs)) {
            throw new \RuntimeException('Unable to load the certificates.');
        }

        return self::createFromKey($certs['pkey'], null, $additional_values);
    }

    /**
     * This method will try to convert a X.509 certificate into a public key.
     */
    public static function createFromCertificate(string $certificate, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadKeyFromCertificate($certificate);
        $values = \array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * This method will try to convert a X.509 certificate resource into a public key.
     *
     * @param resource $res
     *
     * @throws \Exception
     */
    public static function createFromX509Resource($res, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadKeyFromX509Resource($res);
        $values = \array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * This method will try to load and convert a key file into a JWK object.
     * If the key is encrypted, the password must be set.
     *
     * @throws \Exception
     */
    public static function createFromKeyFile(string $file, ?string $password = null, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadFromKeyFile($file, $password);
        $values = \array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * This method will try to load and convert a key into a JWK object.
     * If the key is encrypted, the password must be set.
     *
     * @throws \Exception
     */
    public static function createFromKey(string $key, ?string $password = null, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadFromKey($key, $password);
        $values = \array_merge($values, $additional_values);

        return JWK::create($values);
    }

    /**
     * This method will try to load and convert a X.509 certificate chain into a public key.
     */
    public static function createFromX5C(array $x5c, array $additional_values = []): JWK
    {
        $values = KeyConverter::loadFromX5C($x5c);
        $values = \array_merge($values, $additional_values);

        return JWK::create($values);
    }
}

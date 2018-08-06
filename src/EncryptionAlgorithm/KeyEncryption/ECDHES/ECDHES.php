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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Ecc\Curve;
use Jose\Component\Core\Util\Ecc\NistCurve;
use Jose\Component\Core\Util\Ecc\PrivateKey;
use Jose\Component\Encryption\Util\ConcatKDF;
use Jose\Component\Encryption\Util\Ecc\EcDH;

final class ECDHES implements KeyAgreement
{
    public function allowedKeyTypes(): array
    {
        return ['EC', 'OKP'];
    }

    public function getAgreementKey(int $encryption_key_length, string $algorithm, JWK $recipient_key, array $complete_header = [], array &$additional_header_values = []): string
    {
        if ($recipient_key->has('d')) {
            list($public_key, $private_key) = $this->getKeysFromPrivateKeyAndHeader($recipient_key, $complete_header);
        } else {
            list($public_key, $private_key) = $this->getKeysFromPublicKey($recipient_key, $additional_header_values);
        }

        $agreed_key = $this->calculateAgreementKey($private_key, $public_key);

        $apu = \array_key_exists('apu', $complete_header) ? $complete_header['apu'] : '';
        $apv = \array_key_exists('apv', $complete_header) ? $complete_header['apv'] : '';

        return ConcatKDF::generate($agreed_key, $algorithm, $encryption_key_length, $apu, $apv);
    }

    /**
     * @return JWK[]
     */
    private function getKeysFromPublicKey(JWK $recipient_key, array &$additional_header_values): array
    {
        $this->checkKey($recipient_key, false);
        $public_key = $recipient_key;
        switch ($public_key->get('crv')) {
            case 'P-256':
            case 'P-384':
            case 'P-521':
                $private_key = $this->createECKey($public_key->get('crv'));

                break;
            case 'X25519':
                $private_key = $this->createOKPKey('X25519');

                break;
            default:
                throw new \InvalidArgumentException(\sprintf('The curve "%s" is not supported', $public_key->get('crv')));
        }
        $epk = $private_key->toPublic()->all();
        $additional_header_values['epk'] = $epk;

        return [$public_key, $private_key];
    }

    /**
     * @return JWK[]
     */
    private function getKeysFromPrivateKeyAndHeader(JWK $recipient_key, array $complete_header): array
    {
        $this->checkKey($recipient_key, true);
        $private_key = $recipient_key;
        $public_key = $this->getPublicKey($complete_header);
        if ($private_key->get('crv') !== $public_key->get('crv')) {
            throw new \InvalidArgumentException('Curves are different');
        }

        return [$public_key, $private_key];
    }

    /**
     * @throws \InvalidArgumentException
     */
    public function calculateAgreementKey(JWK $private_key, JWK $public_key): string
    {
        switch ($public_key->get('crv')) {
            case 'P-256':
            case 'P-384':
            case 'P-521':
                $curve = $this->getCurve($public_key->get('crv'));

                $rec_x = $this->convertBase64ToGmp($public_key->get('x'));
                $rec_y = $this->convertBase64ToGmp($public_key->get('y'));
                $sen_d = $this->convertBase64ToGmp($private_key->get('d'));

                $priv_key = PrivateKey::create($sen_d);
                $pub_key = $curve->getPublicKeyFrom($rec_x, $rec_y);

                return $this->convertDecToBin(EcDH::computeSharedKey($curve, $pub_key, $priv_key));
            case 'X25519':
                $sKey = Base64Url::decode($private_key->get('d'));
                $recipientPublickey = Base64Url::decode($public_key->get('x'));

                return \sodium_crypto_scalarmult($sKey, $recipientPublickey);
            default:
                throw new \InvalidArgumentException(\sprintf('The curve "%s" is not supported', $public_key->get('crv')));
        }
    }

    public function name(): string
    {
        return 'ECDH-ES';
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_AGREEMENT;
    }

    /**
     * @return JWK
     */
    private function getPublicKey(array $complete_header)
    {
        if (!\array_key_exists('epk', $complete_header)) {
            throw new \InvalidArgumentException('The header parameter "epk" is missing');
        }
        if (!\is_array($complete_header['epk'])) {
            throw new \InvalidArgumentException('The header parameter "epk" is not an array of parameter');
        }

        $public_key = JWK::create($complete_header['epk']);
        $this->checkKey($public_key, false);

        return $public_key;
    }

    /**
     * @param bool $is_private
     */
    private function checkKey(JWK $key, $is_private)
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        foreach (['x', 'crv'] as $k) {
            if (!$key->has($k)) {
                throw new \InvalidArgumentException(\sprintf('The key parameter "%s" is missing.', $k));
            }
        }

        switch ($key->get('crv')) {
            case 'P-256':
            case 'P-384':
            case 'P-521':
                if (!$key->has('y')) {
                    throw new \InvalidArgumentException('The key parameter "y" is missing.');
                }

                break;
            case 'X25519':
                break;
            default:
                throw new \InvalidArgumentException(\sprintf('The curve "%s" is not supported', $key->get('crv')));
        }
        if (true === $is_private) {
            if (!$key->has('d')) {
                throw new \InvalidArgumentException('The key parameter "d" is missing.');
            }
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function getCurve(string $crv): Curve
    {
        switch ($crv) {
            case 'P-256':
                return NistCurve::curve256();
            case 'P-384':
                return NistCurve::curve384();
            case 'P-521':
                return NistCurve::curve521();
            default:
                throw new \InvalidArgumentException(\sprintf('The curve "%s" is not supported', $crv));
        }
    }

    private function convertBase64ToGmp(string $value): \GMP
    {
        $value = \unpack('H*', Base64Url::decode($value));

        return \gmp_init($value[1], 16);
    }

    private function convertDecToBin(\GMP $dec): string
    {
        if (\gmp_cmp($dec, 0) < 0) {
            throw new \InvalidArgumentException('Unable to convert negative integer to string');
        }

        $hex = \gmp_strval($dec, 16);

        if (0 !== \mb_strlen($hex, '8bit') % 2) {
            $hex = '0'.$hex;
        }

        return \hex2bin($hex);
    }

    /**
     * @param string $crv The curve
     */
    public function createECKey(string $crv): JWK
    {
        try {
            $jwk = self::createECKeyUsingOpenSSL($crv);
        } catch (\Exception $e) {
            $jwk = self::createECKeyUsingPurePhp($crv);
        }

        return JWK::create($jwk);
    }

    /**
     * @param string $curve The curve
     */
    public static function createOKPKey(string $curve): JWK
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

        return JWK::create([
            'kty' => 'OKP',
            'crv' => $curve,
            'x' => Base64Url::encode($x),
            'd' => Base64Url::encode($d),
        ]);
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
            'd' => Base64Url::encode($details['ec']['d']),
            'x' => Base64Url::encode($details['ec']['x']),
            'y' => Base64Url::encode($details['ec']['y']),
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
}

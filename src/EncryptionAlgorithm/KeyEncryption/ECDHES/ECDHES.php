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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Assert\Assertion;
use Base64Url\Base64Url;
use GMP;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Ecc\Curve;
use Jose\Component\Core\Util\Ecc\NistCurve;
use Jose\Component\Core\Util\Ecc\PrivateKey;
use Jose\Component\Core\Util\ECKey;
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

                return sodium_crypto_scalarmult($sKey, $recipientPublickey);
            default:
                throw new InvalidArgumentException(sprintf('The curve "%s" is not supported', $public_key->get('crv')));
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
                $private_key = ECKey::createECKey($public_key->get('crv'));

                break;
            case 'X25519':
                $private_key = $this->createOKPKey('X25519');

                break;
            default:
                throw new InvalidArgumentException(sprintf('The curve "%s" is not supported', $public_key->get('crv')));
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
        Assertion::eq($private_key->get('crv'), $public_key->get('crv'), 'Curves are different');

        return [$public_key, $private_key];
    }

    private function getPublicKey(array $complete_header): JWK
    {
        Assertion::keyExists($complete_header, 'epk', 'The header parameter "epk" is missing');
        Assertion::isArray($complete_header['epk'], 'The header parameter "epk" is not an array of parameter');

        $public_key = new JWK($complete_header['epk']);
        $this->checkKey($public_key, false);

        return $public_key;
    }

    private function checkKey(JWK $key, bool $is_private): void
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        foreach (['x', 'crv'] as $k) {
            Assertion::true($key->has($k), sprintf('The key parameter "%s" is missing.', $k));
        }

        switch ($key->get('crv')) {
            case 'P-256':
            case 'P-384':
            case 'P-521':
                Assertion::true($key->has('y'), 'The key parameter "y" is missing.');

                break;
            case 'X25519':
                break;
            default:
                throw new InvalidArgumentException(sprintf('The curve "%s" is not supported', $key->get('crv')));
        }
        if (true === $is_private) {
            Assertion::true($key->has('d'), 'The key parameter "d" is missing.');
        }
    }

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
                throw new InvalidArgumentException(sprintf('The curve "%s" is not supported', $crv));
        }
    }

    private function convertBase64ToGmp(string $value): GMP
    {
        $value = unpack('H*', Base64Url::decode($value));

        return gmp_init($value[1], 16);
    }

    private function convertDecToBin(GMP $dec): string
    {
        Assertion::lessThan(0, gmp_cmp($dec, 0), 'Unable to convert negative integer to string');
        $hex = gmp_strval($dec, 16);

        if (0 !== mb_strlen($hex, '8bit') % 2) {
            $hex = '0'.$hex;
        }

        return hex2bin($hex);
    }

    /**
     * @param string $curve The curve
     */
    private function createOKPKey(string $curve): JWK
    {
        switch ($curve) {
            case 'X25519':
                $keyPair = sodium_crypto_box_keypair();
                $d = sodium_crypto_box_secretkey($keyPair);
                $x = sodium_crypto_box_publickey($keyPair);

                break;
            case 'Ed25519':
                $keyPair = sodium_crypto_sign_keypair();
                $d = sodium_crypto_sign_secretkey($keyPair);
                $x = sodium_crypto_sign_publickey($keyPair);

                break;
            default:
                throw new InvalidArgumentException(sprintf('Unsupported "%s" curve', $curve));
        }

        return new JWK([
            'kty' => 'OKP',
            'crv' => $curve,
            'x' => Base64Url::encode($x),
            'd' => Base64Url::encode($d),
        ]);
    }
}

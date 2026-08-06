<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use function extension_loaded;
use function is_array;
use function is_string;
use function sprintf;
use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

/**
 * @internal
 */
final readonly class ECKey
{
    /**
     * OID of the id-ecPublicKey algorithm identifier.
     */
    private const EC_PUBLIC_KEY_OID = '1.2.840.10045.2.1';

    public static function convertToPEM(JWK $jwk): string
    {
        if ($jwk->has('d')) {
            return self::convertPrivateKeyToPEM($jwk);
        }

        return self::convertPublicKeyToPEM($jwk);
    }

    /**
     * Converts the key into a PKCS#8 PEM. As PKCS#8 only covers private keys, public keys are converted into a
     * SubjectPublicKeyInfo structure, which is the format expected by the tools consuming PKCS#8 private keys.
     */
    public static function convertToPKCS8PEM(JWK $jwk): string
    {
        if ($jwk->has('d')) {
            return self::convertPrivateKeyToPKCS8PEM($jwk);
        }

        return self::convertPublicKeyToPEM($jwk);
    }

    /**
     * Converts the private key into a PKCS#8 (RFC 5208) PEM, i.e. a PrivateKeyInfo structure wrapping the RFC 5915
     * ECPrivateKey. The curve is only carried by the algorithm identifier: the optional "parameters" field of the
     * inner ECPrivateKey is left out to avoid the duplication, exactly as OpenSSL does.
     */
    public static function convertPrivateKeyToPKCS8PEM(JWK $jwk): string
    {
        $curve = $jwk->get('crv');
        if (! is_string($curve)) {
            throw new InvalidArgumentException('Unable to get the curve');
        }
        $length = (int) ceil(self::getCurveSize($curve) / 8);
        $ecPrivateKey = Sequence::create(
            Integer::create(1),
            OctetString::create(self::getPrivateKeyBytes($jwk, $length)),
            ExplicitlyTaggedType::create(1, BitString::create(self::getKey($jwk))),
        );
        $privateKeyInfo = Sequence::create(
            Integer::create(0),
            Sequence::create(
                ObjectIdentifier::create(self::EC_PUBLIC_KEY_OID),
                ObjectIdentifier::create(self::getCurveOid($curve)),
            ),
            OctetString::create($ecPrivateKey->toDER()),
        );

        return PEM::create(PEM::TYPE_PRIVATE_KEY, $privateKeyInfo->toDER())
            ->string();
    }

    public static function convertPublicKeyToPEM(JWK $jwk): string
    {
        $der = match ($jwk->get('crv')) {
            'P-256' => self::p256PublicKey(),
            'secp256k1' => self::p256KPublicKey(),
            'P-384' => self::p384PublicKey(),
            'P-521' => self::p521PublicKey(),
            'BP-256' => self::bp256PublicKey(),
            'BP-384' => self::bp384PublicKey(),
            'BP-512' => self::bp512PublicKey(),
            default => throw new InvalidArgumentException('Unsupported curve.'),
        };
        $der .= self::getKey($jwk);
        $pem = '-----BEGIN PUBLIC KEY-----' . "\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");

        return $pem . ('-----END PUBLIC KEY-----' . "\n");
    }

    public static function convertPrivateKeyToPEM(JWK $jwk): string
    {
        $der = match ($jwk->get('crv')) {
            'P-256' => self::p256PrivateKey($jwk),
            'secp256k1' => self::p256KPrivateKey($jwk),
            'P-384' => self::p384PrivateKey($jwk),
            'P-521' => self::p521PrivateKey($jwk),
            'BP-256' => self::bp256PrivateKey($jwk),
            'BP-384' => self::bp384PrivateKey($jwk),
            'BP-512' => self::bp512PrivateKey($jwk),
            default => throw new InvalidArgumentException('Unsupported curve.'),
        };
        $der .= self::getKey($jwk);
        $pem = '-----BEGIN EC PRIVATE KEY-----' . "\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");

        return $pem . ('-----END EC PRIVATE KEY-----' . "\n");
    }

    /**
     * Creates a EC key with the given curve and additional values.
     *
     * @param string $curve The curve
     * @param array $values values to configure the key
     */
    public static function createECKey(string $curve, array $values = []): JWK
    {
        $jwk = self::createECKeyUsingOpenSSL($curve);
        $values = array_merge($values, $jwk);

        return new JWK($values);
    }

    private static function getCurveSize(string $curve): int
    {
        return match ($curve) {
            'P-256', 'secp256k1', 'BP-256' => 256,
            'P-384', 'BP-384' => 384,
            'BP-512' => 512,
            'P-521' => 521,
            default => throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve)),
        };
    }

    private static function createECKeyUsingOpenSSL(string $curve): array
    {
        if (! extension_loaded('openssl')) {
            throw new RuntimeException('Please install the OpenSSL extension');
        }
        $key = openssl_pkey_new([
            'curve_name' => self::getOpensslCurveName($curve),
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'private_key_bits' => 2048, // Not used for EC keys. See https://github.com/php/php-src/pull/19103
        ]);
        if ($key === false) {
            throw new RuntimeException('Unable to create the key');
        }
        $result = openssl_pkey_export($key, $out);
        if ($result === false) {
            throw new RuntimeException('Unable to create the key');
        }
        $res = openssl_pkey_get_private($out);
        if ($res === false) {
            throw new RuntimeException('Unable to create the key');
        }
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new InvalidArgumentException('Unable to get the key details');
        }
        $curveSize = self::getCurveSize($curve);

        return [
            'kty' => 'EC',
            'crv' => $curve,
            'd' => Base64UrlSafe::encodeUnpadded(
                str_pad((string) $details['ec']['d'], (int) ceil($curveSize / 8), "\0", STR_PAD_LEFT)
            ),
            'x' => Base64UrlSafe::encodeUnpadded(
                str_pad((string) $details['ec']['x'], (int) ceil($curveSize / 8), "\0", STR_PAD_LEFT)
            ),
            'y' => Base64UrlSafe::encodeUnpadded(
                str_pad((string) $details['ec']['y'], (int) ceil($curveSize / 8), "\0", STR_PAD_LEFT)
            ),
        ];
    }

    /**
     * Returns the OID of the named curve, as used by the AlgorithmIdentifier of the PKCS#8 and SubjectPublicKeyInfo
     * structures.
     */
    private static function getCurveOid(string $curve): string
    {
        return match ($curve) {
            'P-256' => '1.2.840.10045.3.1.7',
            'secp256k1' => '1.3.132.0.10',
            'P-384' => '1.3.132.0.34',
            'P-521' => '1.3.132.0.35',
            'BP-256' => '1.3.36.3.3.2.8.1.1.7',
            'BP-384' => '1.3.36.3.3.2.8.1.1.11',
            'BP-512' => '1.3.36.3.3.2.8.1.1.13',
            default => throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve)),
        };
    }

    private static function getOpensslCurveName(string $curve): string
    {
        return match ($curve) {
            'P-256' => 'prime256v1',
            'secp256k1' => 'secp256k1',
            'P-384' => 'secp384r1',
            'P-521' => 'secp521r1',
            'BP-256' => 'brainpoolP256r1',
            'BP-384' => 'brainpoolP384r1',
            'BP-512' => 'brainpoolP512r1',
            default => throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve)),
        };
    }

    private static function p256PublicKey(): string
    {
        return pack(
            'H*',
            '3059' // SEQUENCE, length 89
            . '3013' // SEQUENCE, length 19
            . '0607' // OID, length 7
            . '2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
            . '0608' // OID, length 8
            . '2a8648ce3d030107' // 1.2.840.10045.3.1.7 = P-256 Curve
            . '0342' // BIT STRING, length 66
            . '00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p256KPublicKey(): string
    {
        return pack(
            'H*',
            '3056' // SEQUENCE, length 86
            . '3010' // SEQUENCE, length 16
            . '0607' // OID, length 7
            . '2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
            . '0605' // OID, length 8
            . '2B8104000A' // 1.3.132.0.10 secp256k1
            . '0342' // BIT STRING, length 66
            . '00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p384PublicKey(): string
    {
        return pack(
            'H*',
            '3076' // SEQUENCE, length 118
            . '3010' // SEQUENCE, length 16
            . '0607' // OID, length 7
            . '2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
            . '0605' // OID, length 5
            . '2b81040022' // 1.3.132.0.34 = P-384 Curve
            . '0362' // BIT STRING, length 98
            . '00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p521PublicKey(): string
    {
        return pack(
            'H*',
            '30819b' // SEQUENCE, length 154
            . '3010' // SEQUENCE, length 16
            . '0607' // OID, length 7
            . '2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
            . '0605' // OID, length 5
            . '2b81040023' // 1.3.132.0.35 = P-521 Curve
            . '038186' // BIT STRING, length 134
            . '00' // prepend with NUL - pubkey will follow
        );
    }

    /**
     * SEQUENCE(90) { SEQUENCE(20) { OID 1.2.840.10045.2.1 = EC Public Key, OID 1.3.36.3.3.2.8.1.1.7 =
     * brainpoolP256r1 }, BIT STRING(66) }
     */
    private static function bp256PublicKey(): string
    {
        return pack('H*', '305a301406072a8648ce3d020106092b2403030208010107034200');
    }

    /**
     * SEQUENCE(122) { SEQUENCE(20) { OID 1.2.840.10045.2.1 = EC Public Key, OID 1.3.36.3.3.2.8.1.1.11 =
     * brainpoolP384r1 }, BIT STRING(98) }
     */
    private static function bp384PublicKey(): string
    {
        return pack('H*', '307a301406072a8648ce3d020106092b240303020801010b036200');
    }

    /**
     * SEQUENCE(155) { SEQUENCE(20) { OID 1.2.840.10045.2.1 = EC Public Key, OID 1.3.36.3.3.2.8.1.1.13 =
     * brainpoolP512r1 }, BIT STRING(130) }
     */
    private static function bp512PublicKey(): string
    {
        return pack('H*', '30819b301406072a8648ce3d020106092b240303020801010d03818200');
    }

    private static function p256PrivateKey(JWK $jwk): string
    {
        return pack(
            'H*',
            '3077' // SEQUENCE, length 87+length($d)=32
            . '020101' // INTEGER, 1
            . '0420'   // OCTET STRING, length($d) = 32
            . self::getPrivateKeyOctets($jwk, 32)
            . 'a00a' // TAGGED OBJECT #0, length 10
            . '0608' // OID, length 8
            . '2a8648ce3d030107' // 1.3.132.0.34 = P-256 Curve
            . 'a144' //  TAGGED OBJECT #1, length 68
            . '0342' // BIT STRING, length 66
            . '00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p256KPrivateKey(JWK $jwk): string
    {
        return pack(
            'H*',
            '3074' // SEQUENCE, length 84+length($d)=32
            . '020101' // INTEGER, 1
            . '0420'   // OCTET STRING, length($d) = 32
            . self::getPrivateKeyOctets($jwk, 32)
            . 'a007' // TAGGED OBJECT #0, length 7
            . '0605' // OID, length 5
            . '2b8104000a' //  1.3.132.0.10 secp256k1
            . 'a144' //  TAGGED OBJECT #1, length 68
            . '0342' // BIT STRING, length 66
            . '00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p384PrivateKey(JWK $jwk): string
    {
        return pack(
            'H*',
            '3081a4' // SEQUENCE, length 116 + length($d)=48
            . '020101' // INTEGER, 1
            . '0430'   // OCTET STRING, length($d) = 30
            . self::getPrivateKeyOctets($jwk, 48)
            . 'a007' // TAGGED OBJECT #0, length 7
            . '0605' // OID, length 5
            . '2b81040022' // 1.3.132.0.34 = P-384 Curve
            . 'a164' //  TAGGED OBJECT #1, length 100
            . '0362' // BIT STRING, length 98
            . '00' // prepend with NUL - pubkey will follow
        );
    }

    private static function p521PrivateKey(JWK $jwk): string
    {
        return pack(
            'H*',
            '3081dc' // SEQUENCE, length 154 + length($d)=66
            . '020101' // INTEGER, 1
            . '0442'   // OCTET STRING, length(d) = 66
            . self::getPrivateKeyOctets($jwk, 66)
            . 'a007' // TAGGED OBJECT #0, length 7
            . '0605' // OID, length 5
            . '2b81040023' // 1.3.132.0.35 = P-521 Curve
            . 'a18189' //  TAGGED OBJECT #1, length 137
            . '038186' // BIT STRING, length 134
            . '00' // prepend with NUL - pubkey will follow
        );
    }

    /**
     * SEQUENCE(120) { INTEGER 1, OCTET STRING(32) = d, [0](11) { OID 1.3.36.3.3.2.8.1.1.7 =
     * brainpoolP256r1 }, [1](68) { BIT STRING(66) } }
     */
    private static function bp256PrivateKey(JWK $jwk): string
    {
        return pack(
            'H*',
            '30780201010420' . self::getPrivateKeyOctets($jwk, 32)
            . 'a00b06092b2403030208010107a144034200'
        );
    }

    /**
     * SEQUENCE(168) { INTEGER 1, OCTET STRING(48) = d, [0](11) { OID 1.3.36.3.3.2.8.1.1.11 =
     * brainpoolP384r1 }, [1](100) { BIT STRING(98) } }
     */
    private static function bp384PrivateKey(JWK $jwk): string
    {
        return pack(
            'H*',
            '3081a80201010430' . self::getPrivateKeyOctets($jwk, 48)
            . 'a00b06092b240303020801010ba164036200'
        );
    }

    /**
     * SEQUENCE(218) { INTEGER 1, OCTET STRING(64) = d, [0](11) { OID 1.3.36.3.3.2.8.1.1.13 =
     * brainpoolP512r1 }, [1](133) { BIT STRING(130) } }
     */
    private static function bp512PrivateKey(JWK $jwk): string
    {
        return pack(
            'H*',
            '3081da0201010440' . self::getPrivateKeyOctets($jwk, 64)
            . 'a00b06092b240303020801010da1818503818200'
        );
    }

    /**
     * Returns the hexadecimal representation of the private key, left-padded to the size of the curve.
     */
    private static function getPrivateKeyOctets(JWK $jwk, int $length): string
    {
        $data = unpack('H*', self::getPrivateKeyBytes($jwk, $length));
        if (! is_array($data) || ! isset($data[1]) || ! is_string($data[1])) {
            throw new InvalidArgumentException('Unable to get the private key');
        }

        return $data[1];
    }

    /**
     * Returns the binary representation of the private key, left-padded to the size of the curve.
     */
    private static function getPrivateKeyBytes(JWK $jwk, int $length): string
    {
        $d = $jwk->get('d');
        if (! is_string($d)) {
            throw new InvalidArgumentException('Unable to get the private key');
        }

        return str_pad(Base64UrlSafe::decodeNoPadding($d), $length, "\0", STR_PAD_LEFT);
    }

    private static function getKey(JWK $jwk): string
    {
        $crv = $jwk->get('crv');
        if (! is_string($crv)) {
            throw new InvalidArgumentException('Unable to get the curve');
        }
        $curveSize = self::getCurveSize($crv);
        $length = (int) ceil($curveSize / 8);
        $x = $jwk->get('x');
        if (! is_string($x)) {
            throw new InvalidArgumentException('Unable to get the public key');
        }
        $y = $jwk->get('y');
        if (! is_string($y)) {
            throw new InvalidArgumentException('Unable to get the public key');
        }
        $binX = ltrim(Base64UrlSafe::decodeNoPadding($x), "\0");
        $binY = ltrim(Base64UrlSafe::decodeNoPadding($y), "\0");

        return "\04"
            . str_pad($binX, $length, "\0", STR_PAD_LEFT)
            . str_pad($binY, $length, "\0", STR_PAD_LEFT)
        ;
    }
}

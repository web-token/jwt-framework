<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE;

use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Throwable;
use function array_key_exists;
use function is_string;
use function ltrim;
use function sprintf;
use function str_pad;
use function strlen;
use const STR_PAD_LEFT;

/**
 * Turns the JWKs and the header parameters of a JWE into the inputs of HPKE (draft-ietf-jose-hpke-encrypt sections 4
 * and 9): the serialized keys of the recipient, and the pre-shared key and its identifier.
 *
 * The keys of the recipient are EC keys on P-256, P-384 or P-521 and OKP keys on X25519 or X448, on the curve of the
 * KEM. The coordinates of an EC key are left-padded to the size of the curve, as ECKey does.
 *
 * The pre-shared key is the sender key: a symmetric key ("kty": "oct") of at least 32 bytes. The "psk_id" header
 * parameter, set by the application, is the base64url encoding of its identifier; when the key has a "kid", it must
 * be that identifier. A pre-shared key and a "psk_id" go together: a pre-shared key given to the decrypter is never
 * ignored, so that a token encrypted in mode_base, which anyone holding the public key can produce, is not accepted
 * where the sender is expected to be authenticated.
 *
 * @internal
 */
final readonly class KeyMaterial
{
    public const PSK_ID = 'psk_id';

    private const PSK_MIN_LENGTH = 32;

    public static function getPublicKey(DHKEM $kem, JWK $key): string
    {
        self::checkKey($kem, $key);
        if ($kem->keyType() === 'OKP') {
            $x = Base64UrlSafe::decodeNoPadding($key->getString('x'));
            if (strlen($x) !== $kem->publicKeyLength) {
                throw new InvalidKeyException('Invalid key parameter "x".');
            }

            return $x;
        }
        $coordinateLength = intdiv($kem->publicKeyLength - 1, 2);

        return "\x04"
            . self::pad(Base64UrlSafe::decodeNoPadding($key->getString('x')), $coordinateLength, 'x')
            . self::pad(Base64UrlSafe::decodeNoPadding($key->getString('y')), $coordinateLength, 'y');
    }

    public static function getPrivateKey(DHKEM $kem, JWK $key): string
    {
        self::checkKey($kem, $key);
        if (! $key->has('d')) {
            throw new InvalidKeyException('The key is not a private key.');
        }
        $d = Base64UrlSafe::decodeNoPadding($key->getString('d'));
        if ($kem->keyType() === 'OKP') {
            if (strlen($d) !== $kem->privateKeyLength) {
                throw new InvalidKeyException('Invalid key parameter "d".');
            }

            return $d;
        }

        return self::pad($d, $kem->privateKeyLength, 'd');
    }

    /**
     * @param array<string, mixed> $header
     *
     * @return array{string, string} The pre-shared key and its identifier, both empty for mode_base
     */
    public static function getPreSharedKey(?JWK $senderKey, array $header): array
    {
        $hasIdentifier = array_key_exists(self::PSK_ID, $header);
        if ($senderKey === null) {
            if ($hasIdentifier) {
                throw new InvalidKeyException(
                    'The header parameter "psk_id" identifies a pre-shared key: it shall be given as the sender key.'
                );
            }

            return ['', ''];
        }
        if (! $hasIdentifier) {
            throw new InvalidHeaderParameterException(
                'The header parameter "psk_id" is missing: it identifies the pre-shared key given as the sender key.'
            );
        }
        $identifier = self::decodeIdentifier($header[self::PSK_ID]);
        if ($senderKey->kty() !== 'oct') {
            throw new InvalidKeyException('The pre-shared key shall be a symmetric key ("kty": "oct").');
        }
        $psk = Base64UrlSafe::decodeNoPadding($senderKey->getString('k'));
        if (strlen($psk) < self::PSK_MIN_LENGTH) {
            throw new InvalidKeyException(sprintf(
                'The pre-shared key shall be at least %d bytes long.',
                self::PSK_MIN_LENGTH
            ));
        }
        if ($senderKey->has('kid') && $senderKey->getString('kid') !== $identifier) {
            throw new InvalidKeyException(
                'The pre-shared key is not the one identified by the header parameter "psk_id".'
            );
        }

        return [$psk, $identifier];
    }

    private static function decodeIdentifier(mixed $value): string
    {
        try {
            $identifier = is_string($value) ? Base64UrlSafe::decodeNoPadding($value) : '';
        } catch (Throwable $throwable) {
            throw new InvalidHeaderParameterException(
                'The header parameter "psk_id" shall be a base64url-encoded string.',
                0,
                $throwable
            );
        }
        if ($identifier === '') {
            throw new InvalidHeaderParameterException(
                'The header parameter "psk_id" shall be a base64url-encoded string.'
            );
        }

        return $identifier;
    }

    private static function checkKey(DHKEM $kem, JWK $key): void
    {
        if ($key->kty() !== $kem->keyType()) {
            throw new InvalidKeyException('Wrong key type.');
        }
        if ($key->find('crv') !== $kem->curve) {
            throw new InvalidKeyException(sprintf('The key shall be on the curve "%s".', $kem->curve));
        }
    }

    private static function pad(string $value, int $length, string $parameter): string
    {
        $value = ltrim($value, "\0");
        if (strlen($value) > $length) {
            throw new InvalidKeyException(sprintf('Invalid key parameter "%s".', $parameter));
        }

        return str_pad($value, $length, "\0", STR_PAD_LEFT);
    }
}

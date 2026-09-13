<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ImplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use Throwable;
use function extension_loaded;
use function is_array;
use function is_string;
use function sprintf;
use function strlen;
use const PHP_VERSION_ID;

/**
 * Algorithm Key Pair keys (RFC 9964 section 3) holding ML-DSA material: the checks the RFC requires, the PEM forms
 * of RFC 9881, key generation and the OpenSSL primitives.
 *
 * The "kty" says nothing about the algorithm, which is why "alg" is REQUIRED on every AKP key (section 3). For the
 * ML-DSA algorithms, the only ones registered for the type, sections 4 and 5 fix the sizes: "priv" is the 32-byte
 * seed of FIPS 204 and nothing else - the expanded private key is deliberately not a representation the RFC allows -
 * and "pub" is the encoded public key of the parameter set. checkKey() enforces both before OpenSSL sees the key
 * (section 7.3), and that "pub" is what the seed expands to when the key carries both (section 7.4).
 *
 * The computation is OpenSSL's: OpenSSL 3.5 ships ML-DSA in its default provider, loads the seed-only
 * PrivateKeyInfo of RFC 9881 and derives the public key from it, and signs and verifies with no digest. Two platform
 * gates follow: PHP 8.4, the first version whose openssl_sign() accepts a null digest, and the OpenSSL library
 * loaded at runtime - which is not always the one PHP was compiled against, so the gate loads an ML-DSA key once per
 * process instead of reading OPENSSL_VERSION_TEXT.
 *
 * @internal
 */
final readonly class AKPKey
{
    public const KEY_TYPE = 'AKP';

    public const ML_DSA_44 = 'ML-DSA-44';

    public const ML_DSA_65 = 'ML-DSA-65';

    public const ML_DSA_87 = 'ML-DSA-87';

    /**
     * RFC 9964 section 4: "the priv parameter MUST be the seed and MUST have a length of 32 bytes".
     */
    public const SEED_LENGTH = 32;

    /**
     * The size of the encoded public key of each parameter set (FIPS 204 table 2, RFC 9964 section 5).
     */
    public const PUBLIC_KEY_LENGTHS = [
        self::ML_DSA_44 => 1312,
        self::ML_DSA_65 => 1952,
        self::ML_DSA_87 => 2592,
    ];

    /**
     * The size of a signature of each parameter set (FIPS 204 table 2, RFC 9964 section 5).
     */
    public const SIGNATURE_LENGTHS = [
        self::ML_DSA_44 => 2420,
        self::ML_DSA_65 => 3309,
        self::ML_DSA_87 => 4627,
    ];

    /**
     * id-ml-dsa-44, id-ml-dsa-65 and id-ml-dsa-87 (RFC 9881 section 3), the algorithm identifiers a
     * SubjectPublicKeyInfo or a PrivateKeyInfo names an ML-DSA key with. They take no parameters.
     */
    public const OIDS = [
        self::ML_DSA_44 => '2.16.840.1.101.3.4.3.17',
        self::ML_DSA_65 => '2.16.840.1.101.3.4.3.18',
        self::ML_DSA_87 => '2.16.840.1.101.3.4.3.19',
    ];

    /**
     * ML-DSA is a one-shot scheme: the message is not hashed beforehand, which OpenSSL expects to be expressed by an
     * empty digest. Any digest is refused by the provider, which is what keeps HashML-DSA out (RFC 9964 section 7.2).
     */
    private const NO_DIGEST = 0;

    /**
     * The PrivateKeyInfo of the all-zero-seed ML-DSA-44 key of RFC 9964 appendix A, in the seed form: an OpenSSL
     * without ML-DSA rejects the algorithm identifier, one with it derives the whole key.
     */
    private const PROBE_KEY = "-----BEGIN PRIVATE KEY-----\nMDQCAQAwCwYJYIZIAWUDBAMRBCKAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAA\n-----END PRIVATE KEY-----\n";

    /**
     * Tells whether the platform can compute ML-DSA: PHP 8.4 or later, and an OpenSSL runtime that provides it.
     */
    public static function supportsOpenSSL(): bool
    {
        return PHP_VERSION_ID >= 80400 && self::isProvidedByOpenSSL();
    }

    /**
     * Tells whether the OpenSSL library PHP loaded provides ML-DSA (3.5 or later). The result is kept for the
     * process.
     */
    public static function isProvidedByOpenSSL(): bool
    {
        /** @var bool|null */
        static $provided = null;
        if ($provided === null) {
            $provided = extension_loaded('openssl') && openssl_pkey_get_private(self::PROBE_KEY) !== false;
            self::lastOpenSSLError();
        }

        return $provided;
    }

    /**
     * The name of the missing piece when supportsOpenSSL() is false, for the exception messages.
     */
    public static function missingDependency(): string
    {
        if (PHP_VERSION_ID < 80400) {
            return 'PHP 8.4 or later, as earlier versions cannot sign or verify without a digest through OpenSSL';
        }

        return 'an OpenSSL library that provides ML-DSA (OpenSSL 3.5 or later), which the one PHP loaded does not';
    }

    /**
     * Checks that the key is an ML-DSA key of the given algorithm, of the shape RFC 9964 requires, before OpenSSL
     * sees it (section 7.3): "alg" present and equal, "pub" of the size of the parameter set, "priv" the 32-byte
     * seed when present, and "pub" the public key the seed expands to (section 7.4).
     */
    public static function checkKey(JWK $key, string $algorithm): void
    {
        if ($key->get('kty') !== self::KEY_TYPE) {
            throw new InvalidKeyException('Wrong key type.');
        }
        $alg = $key->find('alg');
        if ($alg === null) {
            throw new InvalidKeyException(
                'The AKP key carries no "alg" parameter: nothing says which algorithm it belongs to.'
            );
        }
        if ($alg !== $algorithm) {
            throw new InvalidKeyException(sprintf(
                'The AKP key belongs to the algorithm "%s" and cannot be used with "%s".',
                is_string($alg) ? $alg : 'unknown',
                $algorithm
            ));
        }
        $pub = self::publicKey($key, $algorithm);
        if (! $key->has('priv')) {
            return;
        }
        $priv = self::seed($key);
        if (! hash_equals(self::publicKeyFromSeed($algorithm, $priv), $pub)) {
            throw new InvalidKeyException('Invalid AKP key. The "pub" parameter is not the public key the "priv" seed expands to.');
        }
    }

    /**
     * Generates an ML-DSA key of the given parameter set: from a fresh random seed, or from the given one, which is
     * how RFC 9964 section 4 wants private keys stored and rebuilt.
     *
     * @param string|null $seed the 32-byte seed of FIPS 204, random when null
     */
    public static function generate(string $algorithm, ?string $seed = null): JWK
    {
        self::assertAlgorithm($algorithm);
        $seed ??= random_bytes(self::SEED_LENGTH);
        if (strlen($seed) !== self::SEED_LENGTH) {
            throw new InvalidKeyException(sprintf('The seed of an ML-DSA key must be %d bytes long.', self::SEED_LENGTH));
        }

        return new JWK([
            'kty' => self::KEY_TYPE,
            'alg' => $algorithm,
            'pub' => Base64UrlSafe::encodeUnpadded(self::publicKeyFromSeed($algorithm, $seed)),
            'priv' => Base64UrlSafe::encodeUnpadded($seed),
        ]);
    }

    /**
     * The encoded public key of FIPS 204 that the seed expands to (algorithm 6, ML-DSA.KeyGen_internal), as OpenSSL
     * derives it: the seed is loaded as a PrivateKeyInfo and the SubjectPublicKeyInfo OpenSSL reports is read back.
     */
    public static function publicKeyFromSeed(string $algorithm, string $seed): string
    {
        self::assertSupported();
        $privateKey = openssl_pkey_get_private(self::seedToPEM($algorithm, $seed));
        if ($privateKey === false) {
            throw new InvalidKeyException(sprintf('Unable to expand the %s seed: %s', $algorithm, self::lastOpenSSLError()));
        }
        $details = openssl_pkey_get_details($privateKey);
        $publicKeyPem = is_array($details) ? ($details['key'] ?? null) : null;
        if (! is_string($publicKeyPem)) {
            throw new RuntimeException('OpenSSL reported no public key for the ML-DSA seed.');
        }

        return Base64UrlSafe::decodeNoPadding(self::loadFromPEM($publicKeyPem)['pub']);
    }

    /**
     * Signs the input with the private key (FIPS 204 algorithm 2, pure mode, empty context).
     *
     * @return non-empty-string
     */
    public static function sign(JWK $key, string $input): string
    {
        self::assertSupported();
        $privateKey = openssl_pkey_get_private(self::convertPrivateKeyToPKCS8PEM($key));
        if ($privateKey === false) {
            throw new InvalidKeyException(sprintf('Unable to load the ML-DSA private key: %s', self::lastOpenSSLError()));
        }
        $signature = '';
        if (! openssl_sign($input, $signature, $privateKey, self::NO_DIGEST) || ! is_string(
            $signature
        ) || $signature === '') {
            throw new RuntimeException(sprintf('Unable to sign the input: %s', self::lastOpenSSLError()));
        }

        return $signature;
    }

    /**
     * Verifies the signature of the input with the public key. A public key OpenSSL cannot load makes the signature
     * invalid: it is a verification outcome, not an error.
     */
    public static function verify(JWK $key, string $input, string $signature): bool
    {
        self::assertSupported();
        $publicKey = openssl_pkey_get_public(self::convertPublicKeyToPEM($key));
        if ($publicKey === false) {
            self::lastOpenSSLError();

            return false;
        }

        return openssl_verify($input, $signature, $publicKey, self::NO_DIGEST) === 1;
    }

    /**
     * Converts the key into the PEM structures of RFC 9881: a PrivateKeyInfo holding the seed - the "seed [0]"
     * choice of the ML-DSA-PrivateKey - for a private key, a SubjectPublicKeyInfo for a public one.
     */
    public static function convertToPKCS8PEM(JWK $key): string
    {
        if ($key->has('priv')) {
            return self::convertPrivateKeyToPKCS8PEM($key);
        }

        return self::convertPublicKeyToPEM($key);
    }

    public static function convertPrivateKeyToPKCS8PEM(JWK $key): string
    {
        $algorithm = self::algorithmOf($key);

        return self::seedToPEM($algorithm, self::seed($key));
    }

    public static function convertPublicKeyToPEM(JWK $key): string
    {
        $algorithm = self::algorithmOf($key);
        $der = Sequence::create(self::algorithmIdentifier($algorithm), BitString::create(self::publicKey($key, $algorithm)));

        return PEM::create(PEM::TYPE_PUBLIC_KEY, $der->toDER())->string();
    }

    /**
     * Tells whether the PEM holds an ML-DSA key: a PrivateKeyInfo or a SubjectPublicKeyInfo whose algorithm
     * identifier is one of the ML-DSA OIDs. Nothing is decoded beyond that identifier.
     */
    public static function isMLDSAPEM(string $pem): bool
    {
        try {
            self::algorithmOfPEM(PEM::fromString($pem));

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Loads the ML-DSA key of a PEM into the values of an AKP JWK: a SubjectPublicKeyInfo gives "pub", a
     * PrivateKeyInfo of RFC 9881 gives "priv" from its seed and "pub" from the public key OpenSSL derives - or from
     * the "both" choice of the ML-DSA-PrivateKey when the PEM carries it. The "expandedKey" choice alone is
     * refused: RFC 9964 section 4 represents a private key by its seed only. The "alg" is the one the OID names.
     *
     * @return array{kty: string, alg: string, pub: string, priv?: string}
     */
    public static function loadFromPEM(string $pem): array
    {
        try {
            $pem = PEM::fromString($pem);
            $algorithm = self::algorithmOfPEM($pem);
            $sequence = Sequence::fromDER($pem->data());
            if ($pem->type() === PEM::TYPE_PUBLIC_KEY) {
                $pub = $sequence->at(1)
                    ->asBitString()
                    ->string();
                self::assertPublicKeyLength($pub, $algorithm);

                return [
                    'kty' => self::KEY_TYPE,
                    'alg' => $algorithm,
                    'pub' => Base64UrlSafe::encodeUnpadded($pub),
                ];
            }
            [$seed, $pub] = self::readMLDSAPrivateKey($sequence->at(2)->asOctetString()->string(), $algorithm);
        } catch (InvalidKeyException|MissingDependencyException|UnsupportedAlgorithmException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidKeyException('Unable to load the ML-DSA key.', 0, $e);
        }

        return [
            'kty' => self::KEY_TYPE,
            'alg' => $algorithm,
            'pub' => Base64UrlSafe::encodeUnpadded($pub),
            'priv' => Base64UrlSafe::encodeUnpadded($seed),
        ];
    }

    /**
     * The algorithm of the ML-DSA key a PEM holds, from the OID of its AlgorithmIdentifier.
     */
    private static function algorithmOfPEM(PEM $pem): string
    {
        $sequence = Sequence::fromDER($pem->data());
        $algorithmIdentifier = match ($pem->type()) {
            PEM::TYPE_PUBLIC_KEY => $sequence->at(0)->asSequence(),
            PEM::TYPE_PRIVATE_KEY => $sequence->at(1)->asSequence(),
            default => throw new InvalidKeyException('Unsupported PEM type.'),
        };
        $oid = $algorithmIdentifier->at(0)
            ->asObjectIdentifier()
            ->oid();
        $algorithm = array_search($oid, self::OIDS, true);
        if ($algorithm === false) {
            throw new UnsupportedAlgorithmException(sprintf('The OID "%s" is not an ML-DSA algorithm.', $oid));
        }

        return $algorithm;
    }

    /**
     * Decodes the ML-DSA-PrivateKey CHOICE of RFC 9881 section 6: "seed [0]", "expandedKey [1]" or "both [2]
     * SEQUENCE { seed, expandedKey }". The seed and the encoded public key are returned; without a public key in
     * the structure, it is derived from the seed.
     *
     * @return array{string, string}
     */
    private static function readMLDSAPrivateKey(string $der, string $algorithm): array
    {
        $element = UnspecifiedType::fromDER($der)->asTagged();
        $seed = match ($element->tag()) {
            0 => $element->asImplicit(Element::TYPE_OCTET_STRING)
                ->asOctetString()
                ->string(),
            2 => $element->asImplicit(Element::TYPE_SEQUENCE)
                ->asSequence()
                ->at(0)
                ->asOctetString()
                ->string(),
            default => throw new InvalidKeyException(
                'The ML-DSA private key is not represented by its seed, which is the only supported representation.'
            ),
        };
        if (strlen($seed) !== self::SEED_LENGTH) {
            throw new InvalidKeyException(sprintf('The seed of an ML-DSA key must be %d bytes long.', self::SEED_LENGTH));
        }

        return [$seed, self::publicKeyFromSeed($algorithm, $seed)];
    }

    private static function seedToPEM(string $algorithm, string $seed): string
    {
        $der = Sequence::create(
            Integer::create(0),
            self::algorithmIdentifier($algorithm),
            OctetString::create(ImplicitlyTaggedType::create(0, OctetString::create($seed))->toDER())
        );

        return PEM::create(PEM::TYPE_PRIVATE_KEY, $der->toDER())->string();
    }

    private static function algorithmIdentifier(string $algorithm): Sequence
    {
        self::assertAlgorithm($algorithm);

        return Sequence::create(ObjectIdentifier::create(self::OIDS[$algorithm]));
    }

    private static function algorithmOf(JWK $key): string
    {
        if ($key->get('kty') !== self::KEY_TYPE) {
            throw new InvalidKeyException('Wrong key type.');
        }
        $alg = $key->find('alg');
        if (! is_string($alg)) {
            throw new InvalidKeyException(
                'The AKP key carries no "alg" parameter: nothing says what its "pub" and "priv" hold.'
            );
        }
        self::assertAlgorithm($alg);

        return $alg;
    }

    private static function publicKey(JWK $key, string $algorithm): string
    {
        $pub = $key->find('pub');
        if (! is_string($pub) || $pub === '') {
            throw new InvalidKeyException('Invalid AKP key. The "pub" parameter is missing or not a string.');
        }
        $pub = Base64UrlSafe::decodeNoPadding($pub);
        self::assertPublicKeyLength($pub, $algorithm);

        return $pub;
    }

    private static function seed(JWK $key): string
    {
        $priv = $key->find('priv');
        if (! is_string($priv) || $priv === '') {
            throw new InvalidKeyException('Invalid AKP key. The "priv" parameter is missing or not a string.');
        }
        $priv = Base64UrlSafe::decodeNoPadding($priv);
        if (strlen($priv) !== self::SEED_LENGTH) {
            throw new InvalidKeyException(sprintf(
                'Invalid AKP key. The "priv" parameter of an ML-DSA key must be the %d-byte seed.',
                self::SEED_LENGTH
            ));
        }

        return $priv;
    }

    private static function assertPublicKeyLength(string $pub, string $algorithm): void
    {
        if (strlen($pub) !== self::PUBLIC_KEY_LENGTHS[$algorithm]) {
            throw new InvalidKeyException(sprintf(
                'Invalid AKP key. The "pub" parameter of an %s key must be %d bytes long.',
                $algorithm,
                self::PUBLIC_KEY_LENGTHS[$algorithm]
            ));
        }
    }

    private static function assertAlgorithm(string $algorithm): void
    {
        if (! isset(self::OIDS[$algorithm])) {
            throw new UnsupportedAlgorithmException(sprintf('The algorithm "%s" is not an ML-DSA algorithm.', $algorithm));
        }
    }

    private static function assertSupported(): void
    {
        if (! self::supportsOpenSSL()) {
            throw new MissingDependencyException(sprintf('ML-DSA requires %s.', self::missingDependency()));
        }
    }

    private static function lastOpenSSLError(): string
    {
        $message = 'unknown error';
        while (($error = openssl_error_string()) !== false) {
            $message = $error;
        }

        return $message;
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\Exception\UnsupportedCurveException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;
use Jose\Component\KeyManagement\KeyConverter\RSAKey;
use OpenSSLCertificate;
use Override;
use Throwable;
use function array_key_exists;
use function extension_loaded;
use function is_array;
use function is_string;
use function sprintf;
use function strlen;
use function trigger_deprecation;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_KEYTYPE_RSA;

/**
 * The default implementation of the key factory.
 *
 * The class used to be a bag of static methods, several of which reach for OpenSSL, for sodium or for the filesystem.
 * It is an ordinary service now: it is registered in the bundle, it can be injected through JWKFactoryInterface and it
 * can be decorated. The static methods are kept as thin delegations to a default instance and are deprecated; they are
 * removed in 5.0.0.
 *
 * @final The class will be final and readonly in 5.0.0: implement JWKFactoryInterface and decorate the service instead
 * of extending it.
 *
 * @see \Jose\Tests\Component\KeyManagement\JWKFactoryTest
 */
class JWKFactory implements JWKFactoryInterface
{
    public function __construct()
    {
        InheritanceChecker::warnIfExtended(static::class, self::class, JWKFactoryInterface::class);
    }

    /**
     * Creates a RSA key with the given key size and additional values.
     *
     * @param int $size The key size in bits
     * @param array<string, mixed> $values values to configure the key
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "rsa()" instead.
     */
    public static function createRSAKey(int $size, array $values = []): JWK
    {
        self::deprecateStaticCall('createRSAKey', 'rsa');

        return (new self())->rsa($size, $values);
    }

    /**
     * Creates a EC key with the given curve and additional values.
     *
     * @param string $curve The curve
     * @param array<string, mixed> $values values to configure the key
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "ec()" instead.
     */
    public static function createECKey(string $curve, array $values = []): JWK
    {
        self::deprecateStaticCall('createECKey', 'ec');

        return (new self())->ec($curve, $values);
    }

    /**
     * Creates a octet key with the given key size and additional values.
     *
     * @param int $size The key size in bits
     * @param array<string, mixed> $values values to configure the key
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "oct()" instead.
     */
    public static function createOctKey(int $size, array $values = []): JWK
    {
        self::deprecateStaticCall('createOctKey', 'oct');

        return (new self())->oct($size, $values);
    }

    /**
     * Creates a OKP key with the given curve and additional values.
     *
     * @param string $curve The curve
     * @param array<string, mixed> $values values to configure the key
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "okp()" instead.
     */
    public static function createOKPKey(string $curve, array $values = []): JWK
    {
        self::deprecateStaticCall('createOKPKey', 'okp');

        return (new self())->okp($curve, $values);
    }

    /**
     * Creates a none key with the given additional values. Please note that this key type is not part of any
     * specification. It is used to prevent the use of the "none" algorithm with other key types.
     *
     * @param array<string, mixed> $values values to configure the key
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "none()" instead.
     */
    public static function createNoneKey(array $values = []): JWK
    {
        self::deprecateStaticCall('createNoneKey', 'none');

        return (new self())->none($values);
    }

    /**
     * Creates a key from a Json string.
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromJsonObject()"
     *             instead.
     */
    public static function createFromJsonObject(string $value): JWK|JWKSet
    {
        self::deprecateStaticCall('createFromJsonObject', 'fromJsonObject');

        return (new self())->fromJsonObject($value);
    }

    /**
     * Creates a key or key set from the given input.
     *
     * @param array<string, mixed> $values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromValues()"
     *             instead.
     */
    public static function createFromValues(array $values): JWK|JWKSet
    {
        self::deprecateStaticCall('createFromValues', 'fromValues');

        return (new self())->fromValues($values);
    }

    /**
     * This method create a JWK object using a shared secret.
     *
     * @param array<string, mixed> $additional_values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromSecret()"
     *             instead.
     */
    public static function createFromSecret(string $secret, array $additional_values = []): JWK
    {
        self::deprecateStaticCall('createFromSecret', 'fromSecret');

        return (new self())->fromSecret($secret, $additional_values);
    }

    /**
     * This method will try to load a X.509 certificate and convert it into a public key.
     *
     * @param array<string, mixed> $additional_values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call
     *             "fromCertificateFile()" instead.
     */
    public static function createFromCertificateFile(string $file, array $additional_values = []): JWK
    {
        self::deprecateStaticCall('createFromCertificateFile', 'fromCertificateFile');

        return (new self())->fromCertificateFile($file, $additional_values);
    }

    /**
     * Extract a keyfrom a key set identified by the given index .
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromKeySet()"
     *             instead.
     */
    public static function createFromKeySet(JWKSet $jwkset, int|string $index): JWK
    {
        self::deprecateStaticCall('createFromKeySet', 'fromKeySet');

        return (new self())->fromKeySet($jwkset, $index);
    }

    /**
     * This method will try to load a PKCS#12 file and convert it into a public key.
     *
     * @param array<string, mixed> $additional_values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call
     *             "fromPKCS12CertificateFile()" instead.
     */
    public static function createFromPKCS12CertificateFile(
        string $file,
        string $secret = '',
        array $additional_values = []
    ): JWK {
        self::deprecateStaticCall('createFromPKCS12CertificateFile', 'fromPKCS12CertificateFile');

        return (new self())->fromPKCS12CertificateFile($file, $secret, $additional_values);
    }

    /**
     * This method will try to convert a X.509 certificate into a public key.
     *
     * @param array<string, mixed> $additional_values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromCertificate()"
     *             instead.
     */
    public static function createFromCertificate(string $certificate, array $additional_values = []): JWK
    {
        self::deprecateStaticCall('createFromCertificate', 'fromCertificate');

        return (new self())->fromCertificate($certificate, $additional_values);
    }

    /**
     * This method will try to convert a X.509 certificate resource into a public key.
     *
     * @param array<string, mixed> $additional_values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromX509Resource()"
     *             instead.
     */
    public static function createFromX509Resource(OpenSSLCertificate $res, array $additional_values = []): JWK
    {
        self::deprecateStaticCall('createFromX509Resource', 'fromX509Resource');

        return (new self())->fromX509Resource($res, $additional_values);
    }

    /**
     * This method will try to load and convert a key file into a JWK object. If the key is encrypted, the password must
     * be set.
     *
     * @param array<string, mixed> $additional_values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromKeyFile()"
     *             instead.
     */
    public static function createFromKeyFile(string $file, ?string $password = null, array $additional_values = []): JWK
    {
        self::deprecateStaticCall('createFromKeyFile', 'fromKeyFile');

        return (new self())->fromKeyFile($file, $password, $additional_values);
    }

    /**
     * This method will try to load and convert a key into a JWK object. If the key is encrypted, the password must be
     * set.
     *
     * @param array<string, mixed> $additional_values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromKey()" instead.
     */
    public static function createFromKey(string $key, ?string $password = null, array $additional_values = []): JWK
    {
        self::deprecateStaticCall('createFromKey', 'fromKey');

        return (new self())->fromKey($key, $password, $additional_values);
    }

    /**
     * This method will try to load and convert a X.509 certificate chain into a public key.
     *
     * Be careful! The certificate chain is loaded, but it is NOT VERIFIED by any mean! It is mandatory to verify the
     * root CA or intermediate  CA are trusted. If not done, it may lead to potential security issues.
     *
     * @param array<array-key, mixed> $x5c
     * @param array<string, mixed> $additional_values
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. Inject "JWKFactoryInterface" and call "fromX5C()" instead.
     */
    public static function createFromX5C(array $x5c, array $additional_values = []): JWK
    {
        self::deprecateStaticCall('createFromX5C', 'fromX5C');

        return (new self())->fromX5C($x5c, $additional_values);
    }

    #[Override]
    public function rsa(int $size, array $values = []): JWK
    {
        if (! extension_loaded('openssl')) {
            throw new MissingDependencyException('Please install the OpenSSL extension');
        }
        if ($size % 8 !== 0) {
            throw new InvalidKeyException('Invalid key size.');
        }
        if ($size < 512) {
            throw new InvalidKeyException('Key length is too short. It needs to be at least 512 bits.');
        }

        $key = openssl_pkey_new([
            'private_key_bits' => $size,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($key === false) {
            throw new InvalidKeyException('Unable to create the key');
        }
        $details = openssl_pkey_get_details($key);
        if (! is_array($details)) {
            throw new InvalidKeyException('Unable to create the key');
        }
        $rsa = RSAKey::createFromKeyDetails($details['rsa']);
        $values = array_merge($values, $rsa->toArray());

        return new JWK($values);
    }

    #[Override]
    public function ec(string $curve, array $values = []): JWK
    {
        return ECKey::createECKey($curve, $values);
    }

    #[Override]
    public function oct(int $size, array $values = []): JWK
    {
        if ($size < 8 || $size % 8 !== 0) {
            throw new InvalidKeyException('Invalid key size.');
        }

        return $this->fromSecret(random_bytes(max(1, intdiv($size, 8))), $values);
    }

    #[Override]
    public function okp(string $curve, array $values = []): JWK
    {
        if (! extension_loaded('sodium')) {
            throw new MissingDependencyException('The extension "sodium" is not available. Please install it to use this method');
        }

        switch ($curve) {
            case 'X25519':
                $keyPair = sodium_crypto_box_keypair();
                $d = sodium_crypto_box_secretkey($keyPair);
                $x = sodium_crypto_box_publickey($keyPair);

                break;

            case 'Ed25519':
                $keyPair = sodium_crypto_sign_keypair();
                $secret = sodium_crypto_sign_secretkey($keyPair);
                $secretLength = strlen($secret);
                $d = substr($secret, 0, -$secretLength / 2);
                $x = sodium_crypto_sign_publickey($keyPair);

                break;

            default:
                throw new UnsupportedCurveException(sprintf('Unsupported "%s" curve', $curve));
        }

        $values = [
            ...$values,
            'kty' => 'OKP',
            'crv' => $curve,
            'd' => Base64UrlSafe::encodeUnpadded($d),
            'x' => Base64UrlSafe::encodeUnpadded($x),
        ];

        return new JWK($values);
    }

    #[Override]
    public function none(array $values = []): JWK
    {
        $values = [
            ...$values,
            'kty' => 'none',
            'alg' => 'none',
            'use' => 'sig',
        ];

        return new JWK($values);
    }

    #[Override]
    public function fromJsonObject(string $value): JWK|JWKSet
    {
        $json = json_decode($value, true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($json)) {
            throw new InvalidKeyException('Invalid key or key set.');
        }
        /** @var array<string, mixed> $json */
        return $this->fromValues($json);
    }

    #[Override]
    public function fromValues(array $values): JWK|JWKSet
    {
        if (array_key_exists('keys', $values) && is_array($values['keys'])) {
            return JWKSet::createFromKeyData($values);
        }

        return new JWK($values);
    }

    #[Override]
    public function fromSecret(string $secret, array $additionalValues = []): JWK
    {
        $values = array_merge(
            $additionalValues,
            [
                'kty' => 'oct',
                'k' => Base64UrlSafe::encodeUnpadded($secret),
            ]
        );

        return new JWK($values);
    }

    #[Override]
    public function fromCertificateFile(string $file, array $additionalValues = []): JWK
    {
        $values = KeyConverter::loadKeyFromCertificateFile($file);
        $values = array_merge($values, $additionalValues);

        return new JWK($values);
    }

    #[Override]
    public function fromKeySet(JWKSet $jwkset, int|string $index): JWK
    {
        return $jwkset->get($index);
    }

    #[Override]
    public function fromPKCS12CertificateFile(string $file, string $secret = '', array $additionalValues = []): JWK
    {
        try {
            $content = file_get_contents($file);
            if (! is_string($content)) {
                throw new RuntimeException('Unable to read the file.');
            }
            openssl_pkcs12_read($content, $certs, $secret);
            if (! is_array($certs) || ! array_key_exists('pkey', $certs)) {
                throw new RuntimeException('Unable to load the certificates.');
            }
            /** @var array{pkey: string} $certs */
            return $this->fromKey($certs['pkey'], null, $additionalValues);
        } catch (Throwable $throwable) {
            throw new RuntimeException('Unable to load the certificates.', $throwable->getCode(), $throwable);
        }
    }

    #[Override]
    public function fromCertificate(string $certificate, array $additionalValues = []): JWK
    {
        $values = KeyConverter::loadKeyFromCertificate($certificate);
        $values = array_merge($values, $additionalValues);

        return new JWK($values);
    }

    #[Override]
    public function fromX509Resource(OpenSSLCertificate $res, array $additionalValues = []): JWK
    {
        $values = KeyConverter::loadKeyFromX509Resource($res);
        $values = array_merge($values, $additionalValues);

        return new JWK($values);
    }

    #[Override]
    public function fromKeyFile(string $file, ?string $password = null, array $additionalValues = []): JWK
    {
        $values = KeyConverter::loadFromKeyFile($file, $password);
        $values = array_merge($values, $additionalValues);

        return new JWK($values);
    }

    #[Override]
    public function fromKey(string $key, ?string $password = null, array $additionalValues = []): JWK
    {
        $values = KeyConverter::loadFromKey($key, $password);
        $values = array_merge($values, $additionalValues);

        return new JWK($values);
    }

    #[Override]
    public function fromX5C(array $x5c, array $additionalValues = []): JWK
    {
        $values = KeyConverter::loadFromX5C($x5c);
        $values = array_merge($values, $additionalValues);

        return new JWK($values);
    }

    /**
     * Raises the notice emitted when one of the static methods is used instead of the service.
     */
    private static function deprecateStaticCall(string $method, string $replacement): void
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::%s()" is deprecated and will be removed in 5.0.0. Inject "%s" and call "%s()" instead.',
            self::class,
            $method,
            JWKFactoryInterface::class,
            $replacement
        );
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use OpenSSLCertificate;

/**
 * Creates keys and key sets.
 *
 * Several of those methods reach for OpenSSL, for sodium or for the filesystem, which is why the factory is a service
 * and not a bag of static methods any more: application code that generates or loads keys can now depend on this
 * interface, be unit tested without any of them, and be decorated to audit, cache or delegate the generation to a
 * hardware backed implementation.
 */
interface JWKFactoryInterface
{
    /**
     * Creates a RSA key with the given key size and additional values.
     *
     * @param int                  $size   The key size in bits
     * @param array<string, mixed> $values Values to configure the key
     */
    public function rsa(int $size, array $values = []): JWK;

    /**
     * Creates an EC key with the given curve and additional values.
     *
     * @param string               $curve  The curve
     * @param array<string, mixed> $values Values to configure the key
     */
    public function ec(string $curve, array $values = []): JWK;

    /**
     * Creates an octet key with the given key size and additional values.
     *
     * @param int                  $size   The key size in bits
     * @param array<string, mixed> $values Values to configure the key
     */
    public function oct(int $size, array $values = []): JWK;

    /**
     * Creates an OKP key with the given curve and additional values.
     *
     * @param string               $curve  The curve
     * @param array<string, mixed> $values Values to configure the key
     */
    public function okp(string $curve, array $values = []): JWK;

    /**
     * Creates a none key with the given additional values. Please note that this key type is not part of any
     * specification. It is used to prevent the use of the "none" algorithm with other key types.
     *
     * @param array<string, mixed> $values Values to configure the key
     */
    public function none(array $values = []): JWK;

    /**
     * Creates a key or a key set from a JSON string.
     */
    public function fromJsonObject(string $value): JWK|JWKSet;

    /**
     * Creates a key or a key set from the given input.
     *
     * @param array<string, mixed> $values
     */
    public function fromValues(array $values): JWK|JWKSet;

    /**
     * Creates a key using a shared secret.
     *
     * @param array<string, mixed> $additionalValues
     */
    public function fromSecret(string $secret, array $additionalValues = []): JWK;

    /**
     * Loads a X.509 certificate file and converts it into a public key.
     *
     * @param array<string, mixed> $additionalValues
     */
    public function fromCertificateFile(string $file, array $additionalValues = []): JWK;

    /**
     * Extracts a key from a key set, identified by the given index.
     */
    public function fromKeySet(JWKSet $jwkset, int|string $index): JWK;

    /**
     * Loads a PKCS#12 file and converts it into a public key.
     *
     * @param array<string, mixed> $additionalValues
     */
    public function fromPKCS12CertificateFile(string $file, string $secret = '', array $additionalValues = []): JWK;

    /**
     * Converts a X.509 certificate into a public key.
     *
     * @param array<string, mixed> $additionalValues
     */
    public function fromCertificate(string $certificate, array $additionalValues = []): JWK;

    /**
     * Converts a X.509 certificate resource into a public key.
     *
     * @param array<string, mixed> $additionalValues
     */
    public function fromX509Resource(OpenSSLCertificate $res, array $additionalValues = []): JWK;

    /**
     * Loads a key file and converts it into a JWK object. If the key is encrypted, the password must be set.
     *
     * @param array<string, mixed> $additionalValues
     */
    public function fromKeyFile(string $file, ?string $password = null, array $additionalValues = []): JWK;

    /**
     * Loads a key and converts it into a JWK object. If the key is encrypted, the password must be set.
     *
     * @param array<string, mixed> $additionalValues
     */
    public function fromKey(string $key, ?string $password = null, array $additionalValues = []): JWK;

    /**
     * Loads a X.509 certificate chain and converts it into a public key.
     *
     * Be careful! The certificate chain is loaded, but it is NOT VERIFIED by any mean! It is mandatory to verify the
     * root CA or intermediate CA are trusted. If not done, it may lead to potential security issues.
     *
     * @param array<array-key, mixed> $x5c
     * @param array<string, mixed> $additionalValues
     */
    public function fromX5C(array $x5c, array $additionalValues = []): JWK;
}

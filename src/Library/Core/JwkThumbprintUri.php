<?php

declare(strict_types=1);

namespace Jose\Component\Core;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Stringable;
use function array_key_exists;
use function count;
use function sprintf;
use function strlen;

/**
 * A JWK Thumbprint URI, as defined by RFC 9278.
 *
 * The URI "urn:ietf:params:oauth:jwk-thumbprint:<hash-alg>:<thumbprint>" identifies a key by the RFC 7638
 * thumbprint of its public members. "<hash-alg>" is a name from the IANA "Named Information Hash Algorithm"
 * registry ("sha-256", "sha-512", "sha3-256"...) and not the name PHP gives to the same function: this class
 * carries the mapping so that neither the producer nor the verifier has to know it. It is the key-based "sub"
 * or "kid" used by OAuth DPoP, SIOP v2, OpenID for Verifiable Credentials and OpenID Federation.
 *
 * Only the registered names PHP can compute are supported. The truncated variants of the registry ("sha-256-128"
 * and the like) and the BLAKE2 and KangarooTwelve functions are refused, as are names that are not in the
 * registry ("md5", "sha256").
 *
 * @see https://www.rfc-editor.org/rfc/rfc9278.html
 * @see https://www.iana.org/assignments/named-information/named-information.xhtml
 */
final readonly class JwkThumbprintUri implements Stringable
{
    public const PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:';

    public const DEFAULT_HASH_ALGORITHM = 'sha-256';

    /**
     * Maps the IANA name of a hash function to the name PHP's hash() gives to it.
     *
     * @var array<non-empty-string, non-empty-string>
     */
    private const HASH_ALGORITHMS = [
        'sha-256' => 'sha256',
        'sha-384' => 'sha384',
        'sha-512' => 'sha512',
        'sha3-224' => 'sha3-224',
        'sha3-256' => 'sha3-256',
        'sha3-384' => 'sha3-384',
        'sha3-512' => 'sha3-512',
    ];

    /**
     * @param string $hashAlgorithm the IANA name of the hash function, e.g. "sha-256"
     * @param string $thumbprint the RFC 7638 thumbprint, base64url encoded without padding
     */
    private function __construct(
        private string $hashAlgorithm,
        private string $thumbprint
    ) {
    }

    /**
     * Computes the thumbprint URI of the given key.
     *
     * @param string $hashAlgorithm the IANA name of the hash function, "sha-256" by default
     */
    public static function fromKey(JWK $jwk, string $hashAlgorithm = self::DEFAULT_HASH_ALGORITHM): self
    {
        $thumbprint = $jwk->thumbprint(self::phpHashAlgorithm($hashAlgorithm));

        return new self($hashAlgorithm, $thumbprint);
    }

    /**
     * Parses a thumbprint URI. The syntax of the URI and the name of the hash function are checked; the
     * thumbprint itself is only checked to be a non-empty base64url value, as its length depends on the function.
     */
    public static function parse(string $uri): self
    {
        if (! str_starts_with($uri, self::PREFIX)) {
            throw new InvalidArgumentException('The URI is not a JWK Thumbprint URI.');
        }
        $parts = explode(':', substr($uri, strlen(self::PREFIX)));
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new InvalidArgumentException(
                'The JWK Thumbprint URI must be of the form "urn:ietf:params:oauth:jwk-thumbprint:<hash-alg>:<thumbprint>".'
            );
        }
        [$hashAlgorithm, $thumbprint] = $parts;
        self::phpHashAlgorithm($hashAlgorithm);
        if (preg_match('/^[A-Za-z0-9_-]+$/', $thumbprint) !== 1) {
            throw new InvalidArgumentException('The thumbprint of the JWK Thumbprint URI is not base64url encoded.');
        }

        return new self($hashAlgorithm, $thumbprint);
    }

    /**
     * Tells whether the given URI is a JWK Thumbprint URI this class can parse.
     */
    public static function isValid(string $uri): bool
    {
        try {
            self::parse($uri);

            return true;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    /**
     * Lists the supported hash functions, by their IANA name.
     *
     * @return list<non-empty-string>
     */
    public static function hashAlgorithms(): array
    {
        return array_keys(self::HASH_ALGORITHMS);
    }

    /**
     * The IANA name of the hash function, e.g. "sha-256".
     */
    public function hashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    /**
     * The RFC 7638 thumbprint, base64url encoded without padding.
     */
    public function thumbprint(): string
    {
        return $this->thumbprint;
    }

    /**
     * Tells whether the given key is the one this URI identifies: its thumbprint is recomputed with the hash function
     * of the URI and compared in constant time.
     */
    public function matches(JWK $jwk): bool
    {
        return hash_equals($this->thumbprint, $jwk->thumbprint(self::phpHashAlgorithm($this->hashAlgorithm)));
    }

    public function toString(): string
    {
        return self::PREFIX . $this->hashAlgorithm . ':' . $this->thumbprint;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * @return non-empty-string the name PHP's hash() gives to the function
     */
    private static function phpHashAlgorithm(string $hashAlgorithm): string
    {
        if (! array_key_exists($hashAlgorithm, self::HASH_ALGORITHMS)) {
            throw new UnsupportedAlgorithmException(sprintf(
                'The hash algorithm "%s" is not supported for a JWK Thumbprint URI. Supported algorithms: %s.',
                $hashAlgorithm,
                implode(', ', array_keys(self::HASH_ALGORITHMS))
            ));
        }

        return self::HASH_ALGORITHMS[$hashAlgorithm];
    }
}

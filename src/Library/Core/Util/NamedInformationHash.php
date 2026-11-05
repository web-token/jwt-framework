<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use function array_key_exists;
use function sprintf;

/**
 * The hash functions of the IANA "Named Information Hash Algorithm" registry that PHP can compute.
 *
 * The registry names a function "sha-256" where PHP's hash() calls it "sha256": this class carries the mapping for the
 * JWK Thumbprint URI of RFC 9278 and the "_sd_alg" claim of RFC 9901, so that neither the producer nor the verifier has
 * to know it. The truncated variants of the registry ("sha-256-128" and the like) and the BLAKE2 and KangarooTwelve
 * functions are not supported, nor are the names that are not in the registry ("md5", "sha256").
 *
 * @internal
 *
 * @see https://www.iana.org/assignments/named-information/named-information.xhtml
 */
final readonly class NamedInformationHash
{
    /**
     * Maps the IANA name of a hash function to the name PHP's hash() gives to it.
     *
     * @var array<non-empty-string, non-empty-string>
     */
    private const ALGORITHMS = [
        'sha-256' => 'sha256',
        'sha-384' => 'sha384',
        'sha-512' => 'sha512',
        'sha3-224' => 'sha3-224',
        'sha3-256' => 'sha3-256',
        'sha3-384' => 'sha3-384',
        'sha3-512' => 'sha3-512',
    ];

    /**
     * Lists the supported hash functions, by their IANA name.
     *
     * @return list<non-empty-string>
     */
    public static function names(): array
    {
        return array_keys(self::ALGORITHMS);
    }

    public static function isSupported(string $name): bool
    {
        return array_key_exists($name, self::ALGORITHMS);
    }

    /**
     * @return non-empty-string the name PHP's hash() gives to the function
     */
    public static function phpName(string $name): string
    {
        if (! self::isSupported($name)) {
            throw new UnsupportedAlgorithmException(sprintf('The hash algorithm "%s" is not supported.', $name));
        }

        return self::ALGORITHMS[$name];
    }

    /**
     * Computes the binary digest of the data with the function of the given IANA name.
     */
    public static function hash(string $name, string $data): string
    {
        return hash(self::phpName($name), $data, true);
    }
}

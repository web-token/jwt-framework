<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE;

use Jose\Component\Core\Exception\InvalidArgumentException;
use function chr;
use function pack;
use function sprintf;
use function strlen;
use function substr;

/**
 * The two-stage HKDF key derivation functions of HPKE (RFC 5869), and the labeled variants through which HPKE binds
 * every derivation to its version and to the KEM or the cipher suite in use (draft-ietf-hpke-hpke section 4.4).
 *
 * PHP's hash_hkdf() always runs the extract step before the expand step, while HPKE expands pseudorandom keys it has
 * extracted beforehand: both steps are therefore written with hash_hmac(). An empty salt is used as is, since HMAC
 * pads its key with zeros to the block size: it gives the same result as the string of Nh zeros RFC 5869 specifies.
 *
 * @internal
 */
final readonly class HKDF
{
    private const VERSION_LABEL = 'HPKE-v1';

    /**
     * @param int $id The KDF identifier of the HPKE registry
     * @param string $hash The hash function, as known by hash_hmac()
     * @param int $length The output size of the extract step in bytes, Nh
     */
    private function __construct(
        public int $id,
        private string $hash,
        public int $length
    ) {
    }

    public static function fromIdentifier(int $id): self
    {
        return match ($id) {
            0x0001 => self::sha256(),
            0x0002 => self::sha384(),
            0x0003 => self::sha512(),
            default => throw new InvalidArgumentException(sprintf('Unsupported HPKE KDF 0x%04x.', $id)),
        };
    }

    public static function sha256(): self
    {
        return new self(0x0001, 'sha256', 32);
    }

    public static function sha384(): self
    {
        return new self(0x0002, 'sha384', 48);
    }

    public static function sha512(): self
    {
        return new self(0x0003, 'sha512', 64);
    }

    public function extract(string $salt, string $ikm): string
    {
        return hash_hmac($this->hash, $ikm, $salt, true);
    }

    /**
     * T(0) is empty and T(i) = HMAC(prk, T(i - 1) || info || i): the output is the first $length bytes of T(1) || T(2)
     * || ..., at most 255 blocks.
     */
    public function expand(string $prk, string $info, int $length): string
    {
        if ($length < 0 || $length > 255 * $this->length) {
            throw new InvalidArgumentException('Invalid HKDF output length.');
        }
        $output = '';
        $block = '';
        for ($counter = 1; strlen($output) < $length; ++$counter) {
            $block = hash_hmac($this->hash, $block . $info . chr($counter), $prk, true);
            $output .= $block;
        }

        return substr($output, 0, $length);
    }

    public function labeledExtract(string $suiteId, string $salt, string $label, string $ikm): string
    {
        return $this->extract($salt, self::VERSION_LABEL . $suiteId . $label . $ikm);
    }

    public function labeledExpand(string $suiteId, string $prk, string $label, string $info, int $length): string
    {
        return $this->expand($prk, pack('n', $length) . self::VERSION_LABEL . $suiteId . $label . $info, $length);
    }
}

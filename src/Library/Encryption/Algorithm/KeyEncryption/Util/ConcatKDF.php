<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util;

use InvalidArgumentException;
use Jose\Component\Core\Util\Base64UrlSafe;
use const STR_PAD_LEFT;

/**
 * @internal
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.6.2
 */
final class ConcatKDF
{
    /**
     * Key Derivation Function.
     *
     * Each round hashes, with SHA-256, the round number (a 32-bit big-endian counter starting at 1), the shared secret
     * and the OtherInfo value: the length-prefixed algorithm name, PartyUInfo and PartyVInfo, then the key size in
     * bits as SuppPubInfo and an empty SuppPrivInfo. As many rounds as the requested key size needs are concatenated,
     * and the result is truncated to that size.
     *
     * @param string $Z Shared secret
     * @param string $algorithm Encryption algorithm
     * @param int $encryption_key_size Size of the encryption key
     * @param string $apu Agreement PartyUInfo (information about the producer)
     * @param string $apv Agreement PartyVInfo (information about the recipient)
     */
    public static function generate(
        string $Z,
        string $algorithm,
        int $encryption_key_size,
        string $apu = '',
        string $apv = ''
    ): string {
        $apu = ! self::isEmpty($apu) ? Base64UrlSafe::decodeNoPadding($apu) : '';
        $apv = ! self::isEmpty($apv) ? Base64UrlSafe::decodeNoPadding($apv) : '';
        $other_info = implode('', [
            self::toInt32Bits(mb_strlen($algorithm, '8bit')) . $algorithm,
            self::toInt32Bits(mb_strlen($apu, '8bit')) . $apu,
            self::toInt32Bits(mb_strlen($apv, '8bit')) . $apv,
            self::toInt32Bits($encryption_key_size),
            '',
        ]);

        $key_length = intdiv($encryption_key_size, 8);
        $derived_key = '';
        for ($round = 1; mb_strlen($derived_key, '8bit') < $key_length; ++$round) {
            $derived_key .= hash('sha256', self::toInt32Bits($round) . $Z . $other_info, true);
        }

        return mb_substr($derived_key, 0, $key_length, '8bit');
    }

    /**
     * Convert an integer into a 32 bits string.
     *
     * @param int $value Integer to convert
     */
    private static function toInt32Bits(int $value): string
    {
        $result = hex2bin(str_pad(dechex($value), 8, '0', STR_PAD_LEFT));
        if ($result === false) {
            throw new InvalidArgumentException('Invalid result');
        }

        return $result;
    }

    private static function isEmpty(?string $value): bool
    {
        return $value === null || $value === '';
    }
}

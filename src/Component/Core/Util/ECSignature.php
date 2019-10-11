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

namespace Jose\Component\Core\Util;

use InvalidArgumentException;
use const STR_PAD_LEFT;

/**
 * @internal
 */
final class ECSignature
{
    private const ASN1_SEQUENCE = '30';
    private const ASN1_INTEGER = '02';
    private const ASN1_MAX_SINGLE_BYTE = 128;
    private const ASN1_LENGTH_2BYTES = '81';
    private const ASN1_BIG_INTEGER_LIMIT = '7f';
    private const ASN1_NEGATIVE_INTEGER = '00';
    private const BYTE_SIZE = 2;

    /**
     * @throws InvalidArgumentException if the length of the signature is invalid
     */
    public static function toAsn1(string $signature, int $length): string
    {
        $signature = bin2hex($signature);

        if (self::octetLength($signature) !== $length) {
            throw new InvalidArgumentException('Invalid signature length.');
        }

        $pointR = self::preparePositiveInteger(mb_substr($signature, 0, $length, '8bit'));
        $pointS = self::preparePositiveInteger(mb_substr($signature, $length, null, '8bit'));

        $lengthR = self::octetLength($pointR);
        $lengthS = self::octetLength($pointS);

        $totalLength = $lengthR + $lengthS + self::BYTE_SIZE + self::BYTE_SIZE;
        $lengthPrefix = $totalLength > self::ASN1_MAX_SINGLE_BYTE ? self::ASN1_LENGTH_2BYTES : '';

        return hex2bin(
            self::ASN1_SEQUENCE
            .$lengthPrefix.dechex($totalLength)
            .self::ASN1_INTEGER.dechex($lengthR).$pointR
            .self::ASN1_INTEGER.dechex($lengthS).$pointS
        );
    }

    /**
     * @throws InvalidArgumentException if the signature is not an ASN.1 sequence
     */
    public static function fromAsn1(string $signature, int $length): string
    {
        $message = bin2hex($signature);
        $position = 0;

        if (self::ASN1_SEQUENCE !== self::readAsn1Content($message, $position, self::BYTE_SIZE)) {
            throw new InvalidArgumentException('Invalid data. Should start with a sequence.');
        }

        if (self::ASN1_LENGTH_2BYTES === self::readAsn1Content($message, $position, self::BYTE_SIZE)) {
            $position += self::BYTE_SIZE;
        }

        $pointR = self::retrievePositiveInteger(self::readAsn1Integer($message, $position));
        $pointS = self::retrievePositiveInteger(self::readAsn1Integer($message, $position));

        return hex2bin(str_pad($pointR, $length, '0', STR_PAD_LEFT).str_pad($pointS, $length, '0', STR_PAD_LEFT));
    }

    private static function octetLength(string $data): int
    {
        return (int) (mb_strlen($data, '8bit') / self::BYTE_SIZE);
    }

    private static function preparePositiveInteger(string $data): string
    {
        if (mb_substr($data, 0, self::BYTE_SIZE, '8bit') > self::ASN1_BIG_INTEGER_LIMIT) {
            return self::ASN1_NEGATIVE_INTEGER.$data;
        }

        while (0 === mb_strpos($data, self::ASN1_NEGATIVE_INTEGER, 0, '8bit')
            && mb_substr($data, 2, self::BYTE_SIZE, '8bit') <= self::ASN1_BIG_INTEGER_LIMIT) {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }

    private static function readAsn1Content(string $message, int &$position, int $length): string
    {
        $content = mb_substr($message, $position, $length, '8bit');
        $position += $length;

        return $content;
    }

    /**
     * @throws InvalidArgumentException if the data is not an integer
     */
    private static function readAsn1Integer(string $message, int &$position): string
    {
        if (self::ASN1_INTEGER !== self::readAsn1Content($message, $position, self::BYTE_SIZE)) {
            throw new InvalidArgumentException('Invalid data. Should contain an integer.');
        }

        $length = (int) hexdec(self::readAsn1Content($message, $position, self::BYTE_SIZE));

        return self::readAsn1Content($message, $position, $length * self::BYTE_SIZE);
    }

    private static function retrievePositiveInteger(string $data): string
    {
        while (0 === mb_strpos($data, self::ASN1_NEGATIVE_INTEGER, 0, '8bit')
            && mb_substr($data, 2, self::BYTE_SIZE, '8bit') > self::ASN1_BIG_INTEGER_LIMIT) {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }
}

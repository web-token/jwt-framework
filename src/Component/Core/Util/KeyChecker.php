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

use Assert\Assertion;
use InvalidArgumentException;
use Jose\Component\Core\JWK;

/**
 * @internal
 */
class KeyChecker
{
    public static function checkKeyUsage(JWK $key, string $usage): void
    {
        if ($key->has('use')) {
            self::checkUsage($key, $usage);
        }
        if ($key->has('key_ops')) {
            self::checkOperation($key, $usage);
        }
    }

    public static function checkKeyAlgorithm(JWK $key, string $algorithm): void
    {
        if (!$key->has('alg')) {
            return;
        }

        Assertion::eq($key->get('alg'), $algorithm, sprintf('Key is only allowed for algorithm "%s".', $key->get('alg')));
    }

    private static function checkOperation(JWK $key, string $usage): void
    {
        $ops = $key->get('key_ops');
        if (!\is_array($ops)) {
            $ops = [$ops];
        }
        switch ($usage) {
            case 'verification':
                Assertion::inArray('verify', $ops, 'Key cannot be used to verify a signature');

                break;
            case 'signature':
                Assertion::inArray('sign', $ops, 'Key cannot be used to sign');

                break;
            case 'encryption':
                if (!\in_array('encrypt', $ops, true) && !\in_array('wrapKey', $ops, true)) {
                    throw new InvalidArgumentException('Key cannot be used to encrypt');
                }

                break;
            case 'decryption':
                if (!\in_array('decrypt', $ops, true) && !\in_array('unwrapKey', $ops, true)) {
                    throw new InvalidArgumentException('Key cannot be used to decrypt');
                }

                break;
            default:
                throw new InvalidArgumentException('Unsupported key usage.');
        }
    }

    private static function checkUsage(JWK $key, string $usage): void
    {
        $use = $key->get('use');
        switch ($usage) {
            case 'verification':
            case 'signature':
                Assertion::eq($use, 'sig', 'Key cannot be used to sign or verify a signature.');

                break;
            case 'encryption':
            case 'decryption':
            Assertion::eq($use, 'enc', 'Key cannot be used to encrypt or decrypt.');

                break;
            default:
                throw new InvalidArgumentException('Unsupported key usage.');
        }
    }
}

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util;

use Jose\Component\Core\JWK;

/**
 * @internal
 */
class KeyChecker
{
    /**
     * @throws \InvalidArgumentException
     */
    public static function checkKeyUsage(JWK $key, string $usage): bool
    {
        if ($key->has('use')) {
            return self::checkUsage($key, $usage);
        }
        if ($key->has('key_ops')) {
            return self::checkOperation($key, $usage);
        }

        return true;
    }

    private static function checkOperation(JWK $key, string $usage): bool
    {
        $ops = $key->get('key_ops');
        if (!\is_array($ops)) {
            $ops = [$ops];
        }
        switch ($usage) {
            case 'verification':
                if (!\in_array('verify', $ops, true)) {
                    throw new \InvalidArgumentException('Key cannot be used to verify a signature');
                }

                return true;
            case 'signature':
                if (!\in_array('sign', $ops, true)) {
                    throw new \InvalidArgumentException('Key cannot be used to sign');
                }

                return true;
            case 'encryption':
                if (!\in_array('encrypt', $ops, true) && !\in_array('wrapKey', $ops, true)) {
                    throw new \InvalidArgumentException('Key cannot be used to encrypt');
                }

                return true;
            case 'decryption':
                if (!\in_array('decrypt', $ops, true) && !\in_array('unwrapKey', $ops, true)) {
                    throw new \InvalidArgumentException('Key cannot be used to decrypt');
                }

                return true;
            default:
                throw new \InvalidArgumentException('Unsupported key usage.');
        }
    }

    private static function checkUsage(JWK $key, string $usage): bool
    {
        $use = $key->get('use');
        switch ($usage) {
            case 'verification':
            case 'signature':
                if ('sig' !== $use) {
                    throw new \InvalidArgumentException('Key cannot be used to sign or verify a signature.');
                }

                return true;
            case 'encryption':
            case 'decryption':
                if ('enc' !== $use) {
                    throw new \InvalidArgumentException('Key cannot be used to encrypt or decrypt.');
                }

                return true;
            default:
                throw new \InvalidArgumentException('Unsupported key usage.');
        }
    }

    public static function checkKeyAlgorithm(JWK $key, string $algorithm)
    {
        if (!$key->has('alg')) {
            return;
        }

        if ($key->get('alg') !== $algorithm) {
            throw new \InvalidArgumentException(\sprintf('Key is only allowed for algorithm "%s".', $key->get('alg')));
        }
    }
}

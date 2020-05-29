<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Algorithm;

use function in_array;
use InvalidArgumentException;
use Jose\Component\Core\JWK;

final class None implements SignatureAlgorithm
{
    public function allowedKeyTypes(): array
    {
        return ['none'];
    }

    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);

        return '';
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        return '' === $signature;
    }

    public function name(): string
    {
        return 'none';
    }

    /**
     * @throws InvalidArgumentException if the key type is invalid
     */
    private function checkKey(JWK $key): void
    {
        if (!in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
    }
}

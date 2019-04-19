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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

abstract class AESKW implements KeyWrapping
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function wrapKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $k = $this->getKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper::wrap($k, $cek);
    }

    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $k = $this->getKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper::unwrap($k, $encrypted_cek);
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    /**
     * @return \AESKW\A128KW|\AESKW\A192KW|\AESKW\A256KW
     */
    abstract protected function getWrapper();

    private function getKey(JWK $key): string
    {
        Assertion::inArray($key->get('kty'), $this->allowedKeyTypes(), 'Wrong key type.');
        Assertion::true($key->has('k'), 'The key parameter "k" is missing.');
        $k = $key->get('k');
        Assertion::string($k, 'The key parameter "k" is invalid.');

        return Base64Url::decode($k);
    }
}

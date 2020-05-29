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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use function in_array;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;

abstract class RSA implements KeyEncryption
{
    public function allowedKeyTypes(): array
    {
        return ['RSA'];
    }

    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $this->checkKey($key);
        $pub = RSAKey::toPublic(RSAKey::createFromJWK($key));

        return RSACrypt::encrypt($pub, $cek, $this->getEncryptionMode(), $this->getHashAlgorithm());
    }

    /**
     * @throws InvalidArgumentException if the key is not private
     */
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $this->checkKey($key);
        if (!$key->has('d')) {
            throw new InvalidArgumentException('The key is not a private key');
        }
        $priv = RSAKey::createFromJWK($key);

        return RSACrypt::decrypt($priv, $encrypted_cek, $this->getEncryptionMode(), $this->getHashAlgorithm());
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    /**
     * @throws InvalidArgumentException if the key type is not allowed
     */
    protected function checkKey(JWK $key): void
    {
        if (!in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
    }

    abstract protected function getEncryptionMode(): int;

    abstract protected function getHashAlgorithm(): ?string;
}

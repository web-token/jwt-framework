<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;
use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use const Sodium\CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;

/**
 * Class ChaCha20Poly1305.
 * This algorithm is a custom algorithm that use the CChaCha20 + Poly 1305 with a 192 bits nonce (IETF variant).
 */
final class ChaCha20Poly1305IETF implements KeyEncryption
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'ChaCha20+Poly1305+IETF';
    }

    /**
     * {@inheritdoc}
     */
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    /**
     * {@inheritdoc}
     */
    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $this->checkKey($key);
        $kek = Base64Url::decode($key->get('k'));
        $nonce = random_bytes(CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        $additionalHeader['nonce'] = Base64Url::encode($nonce);

        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($cek, '', $nonce, $kek);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $this->checkKey($key);
        $this->checkAdditionalParameters($header);
        $nonce = Base64Url::decode($header['nonce']);
        $kek = Base64Url::decode($key->get('k'));

        $decrypted = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($encrypted_cek, '', $nonce, $kek);
        if ($decrypted === false) {
            throw new \RuntimeException('Unable to decrypt.');
        }

        return $decrypted;
    }

    /**
     * @param JWK $key
     */
    protected function checkKey(JWK $key)
    {
        if (!in_array($key->get('kty'), $this->allowedKeyTypes())) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        if (!$key->has('k')) {
            throw new \InvalidArgumentException('The key parameter "k" is missing.');
        }
    }

    /**
     * @param array $header
     */
    protected function checkAdditionalParameters(array $header)
    {
        foreach (['nonce'] as $k) {
            if (!array_key_exists($k, $header)) {
                throw new \InvalidArgumentException(sprintf('Parameter "%s" is missing.', $k));
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }
}

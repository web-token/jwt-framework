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

namespace Jose\Component\Encryption;

use Base64Url\Base64Url;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryption\DirectEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreement;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementWithKeyWrapping;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrapping;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Encryption\Compression\CompressionMethodManager;

class JWEDecrypter
{
    /**
     * @var AlgorithmManager
     */
    private $keyEncryptionAlgorithmManager;

    /**
     * @var AlgorithmManager
     */
    private $contentEncryptionAlgorithmManager;

    /**
     * @var CompressionMethodManager
     */
    private $compressionMethodManager;

    /**
     * JWEDecrypter constructor.
     */
    public function __construct(AlgorithmManager $keyEncryptionAlgorithmManager, AlgorithmManager $contentEncryptionAlgorithmManager, CompressionMethodManager $compressionMethodManager)
    {
        $this->keyEncryptionAlgorithmManager = $keyEncryptionAlgorithmManager;
        $this->contentEncryptionAlgorithmManager = $contentEncryptionAlgorithmManager;
        $this->compressionMethodManager = $compressionMethodManager;
    }

    /**
     * Returns the key encryption algorithm manager.
     */
    public function getKeyEncryptionAlgorithmManager(): AlgorithmManager
    {
        return $this->keyEncryptionAlgorithmManager;
    }

    /**
     * Returns the content encryption algorithm manager.
     */
    public function getContentEncryptionAlgorithmManager(): AlgorithmManager
    {
        return $this->contentEncryptionAlgorithmManager;
    }

    /**
     * Returns the compression method manager.
     */
    public function getCompressionMethodManager(): CompressionMethodManager
    {
        return $this->compressionMethodManager;
    }

    /**
     * This method will try to decrypt the given JWE and recipient using a JWK.
     *
     * @param JWE $jwe       A JWE object to decrypt
     * @param JWK $jwk       The key used to decrypt the input
     * @param int $recipient The recipient used to decrypt the token
     */
    public function decryptUsingKey(JWE &$jwe, JWK $jwk, int $recipient): bool
    {
        $jwkset = JWKSet::createFromKeys([$jwk]);

        return $this->decryptUsingKeySet($jwe, $jwkset, $recipient);
    }

    /**
     * This method will try to decrypt the given JWE and recipient using a JWKSet.
     *
     * @param JWE    $jwe       A JWE object to decrypt
     * @param JWKSet $jwkset    The key set used to decrypt the input
     * @param int    $recipient The recipient used to decrypt the token
     */
    public function decryptUsingKeySet(JWE &$jwe, JWKSet $jwkset, int $recipient): bool
    {
        $this->checkJWKSet($jwkset);
        $this->checkPayload($jwe);
        $this->checkRecipients($jwe);

        $plaintext = $this->decryptRecipientKey($jwe, $jwkset, $recipient);
        if (null !== $plaintext) {
            $jwe = $jwe->withPayload($plaintext);

            return true;
        }

        return false;
    }

    private function decryptRecipientKey(JWE $jwe, JWKSet $jwkset, int $i): ?string
    {
        $recipient = $jwe->getRecipient($i);
        $completeHeader = \array_merge($jwe->getSharedProtectedHeader(), $jwe->getSharedHeader(), $recipient->getHeader());
        $this->checkCompleteHeader($completeHeader);

        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($completeHeader);
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($completeHeader);

        foreach ($jwkset as $jwk) {
            try {
                KeyChecker::checkKeyUsage($jwk, 'decryption');
                if ('dir' !== $key_encryption_algorithm->name()) {
                    KeyChecker::checkKeyAlgorithm($jwk, $key_encryption_algorithm->name());
                } else {
                    KeyChecker::checkKeyAlgorithm($jwk, $content_encryption_algorithm->name());
                }
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $jwk, $recipient, $completeHeader);
                if (null !== $cek) {
                    return $this->decryptPayload($jwe, $cek, $content_encryption_algorithm, $completeHeader);
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
        }

        return null;
    }

    private function checkRecipients(JWE $jwe)
    {
        if (0 === $jwe->countRecipients()) {
            throw new \InvalidArgumentException('The JWE does not contain any recipient.');
        }
    }

    private function checkPayload(JWE $jwe)
    {
        if (null !== $jwe->getPayload()) {
            throw new \InvalidArgumentException('The JWE is already decrypted.');
        }
    }

    private function checkJWKSet(JWKSet $jwkset)
    {
        if (0 === $jwkset->count()) {
            throw new \InvalidArgumentException('No key in the key set.');
        }
    }

    private function decryptCEK(Algorithm $key_encryption_algorithm, ContentEncryptionAlgorithm $content_encryption_algorithm, JWK $key, Recipient $recipient, array $completeHeader): ?string
    {
        if ($key_encryption_algorithm instanceof DirectEncryption) {
            return $key_encryption_algorithm->getCEK($key);
        }
        if ($key_encryption_algorithm instanceof KeyAgreement) {
            return $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $content_encryption_algorithm->name(), $key, $completeHeader);
        }
        if ($key_encryption_algorithm instanceof KeyAgreementWithKeyWrapping) {
            return $key_encryption_algorithm->unwrapAgreementKey($key, $recipient->getEncryptedKey(), $content_encryption_algorithm->getCEKSize(), $completeHeader);
        }
        if ($key_encryption_algorithm instanceof KeyEncryption) {
            return $key_encryption_algorithm->decryptKey($key, $recipient->getEncryptedKey(), $completeHeader);
        }
        if ($key_encryption_algorithm instanceof KeyWrapping) {
            return $key_encryption_algorithm->unwrapKey($key, $recipient->getEncryptedKey(), $completeHeader);
        } else {
            throw new \InvalidArgumentException('Unsupported CEK generation');
        }
    }

    private function decryptPayload(JWE $jwe, string $cek, ContentEncryptionAlgorithm $content_encryption_algorithm, array $completeHeader): string
    {
        $payload = $content_encryption_algorithm->decryptContent($jwe->getCiphertext(), $cek, $jwe->getIV(), null === $jwe->getAAD() ? null : Base64Url::encode($jwe->getAAD()), $jwe->getEncodedSharedProtectedHeader(), $jwe->getTag());

        return $this->decompressIfNeeded($payload, $completeHeader);
    }

    private function decompressIfNeeded(string $payload, array $completeHeaders): string
    {
        if (\array_key_exists('zip', $completeHeaders)) {
            $compression_method = $this->compressionMethodManager->get($completeHeaders['zip']);
            $payload = $compression_method->uncompress($payload);
            if (!\is_string($payload)) {
                throw new \InvalidArgumentException('Decompression failed');
            }
        }

        return $payload;
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function checkCompleteHeader(array $completeHeaders)
    {
        foreach (['enc', 'alg'] as $key) {
            if (!\array_key_exists($key, $completeHeaders)) {
                throw new \InvalidArgumentException(\sprintf("Parameters '%s' is missing.", $key));
            }
        }
    }

    private function getKeyEncryptionAlgorithm(array $completeHeaders): KeyEncryptionAlgorithm
    {
        $key_encryption_algorithm = $this->keyEncryptionAlgorithmManager->get($completeHeaders['alg']);
        if (!$key_encryption_algorithm instanceof KeyEncryptionAlgorithm) {
            throw new \InvalidArgumentException(\sprintf('The key encryption algorithm "%s" is not supported or does not implement KeyEncryptionAlgorithmInterface.', $completeHeaders['alg']));
        }

        return $key_encryption_algorithm;
    }

    private function getContentEncryptionAlgorithm(array $completeHeader): ContentEncryptionAlgorithm
    {
        $content_encryption_algorithm = $this->contentEncryptionAlgorithmManager->get($completeHeader['enc']);
        if (!$content_encryption_algorithm instanceof ContentEncryptionAlgorithm) {
            throw new \InvalidArgumentException(\sprintf('The key encryption algorithm "%s" is not supported or does not implement ContentEncryptionInterface.', $completeHeader['enc']));
        }

        return $content_encryption_algorithm;
    }
}

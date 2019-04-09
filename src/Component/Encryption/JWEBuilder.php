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

namespace Jose\Component\Encryption;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryption\DirectEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreement;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementWithKeyWrapping;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrapping;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Encryption\Compression\CompressionMethod;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use function Safe\sprintf;

class JWEBuilder
{
    /**
     * @var string|null
     */
    protected $payload;

    /**
     * @var string|null
     */
    protected $aad;

    /**
     * @var array
     */
    protected $recipients = [];

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
    private $compressionManager;

    /**
     * @var array
     */
    protected $sharedProtectedHeader = [];

    /**
     * @var array
     */
    protected $sharedHeader = [];

    /**
     * @var CompressionMethod|null
     */
    private $compressionMethod = null;

    /**
     * @var ContentEncryptionAlgorithm|null
     */
    private $contentEncryptionAlgorithm = null;

    /**
     * @var string|null
     */
    private $keyManagementMode = null;

    public function __construct(AlgorithmManager $keyEncryptionAlgorithmManager, AlgorithmManager $contentEncryptionAlgorithmManager, CompressionMethodManager $compressionManager)
    {
        $this->keyEncryptionAlgorithmManager = $keyEncryptionAlgorithmManager;
        $this->contentEncryptionAlgorithmManager = $contentEncryptionAlgorithmManager;
        $this->compressionManager = $compressionManager;
    }

    /**
     * Reset the current data.
     *
     * @return JWEBuilder
     */
    public function create(): self
    {
        $this->payload = null;
        $this->aad = null;
        $this->recipients = [];
        $this->sharedProtectedHeader = [];
        $this->sharedHeader = [];
        $this->compressionMethod = null;
        $this->contentEncryptionAlgorithm = null;
        $this->keyManagementMode = null;

        return $this;
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
        return $this->compressionManager;
    }

    /**
     * Set the payload of the JWE to build.
     *
     * @return JWEBuilder
     */
    public function withPayload(string $payload): self
    {
        Assertion::eq('UTF-8', \mb_detect_encoding($payload, 'UTF-8', true), 'The payload must be encoded in UTF-8');
        $clone = clone $this;
        $clone->payload = $payload;

        return $clone;
    }

    /**
     * Set the Additional Authenticated Data of the JWE to build.
     *
     * @return JWEBuilder
     */
    public function withAAD(?string $aad): self
    {
        $clone = clone $this;
        $clone->aad = $aad;

        return $clone;
    }

    /**
     * Set the shared protected header of the JWE to build.
     *
     * @return JWEBuilder
     */
    public function withSharedProtectedHeader(array $sharedProtectedHeader): self
    {
        $this->checkDuplicatedHeaderParameters($sharedProtectedHeader, $this->sharedHeader);
        foreach ($this->recipients as $recipient) {
            $this->checkDuplicatedHeaderParameters($sharedProtectedHeader, $recipient->getHeader());
        }
        $clone = clone $this;
        $clone->sharedProtectedHeader = $sharedProtectedHeader;

        return $clone;
    }

    /**
     * Set the shared header of the JWE to build.
     *
     * @return JWEBuilder
     */
    public function withSharedHeader(array $sharedHeader): self
    {
        $this->checkDuplicatedHeaderParameters($this->sharedProtectedHeader, $sharedHeader);
        foreach ($this->recipients as $recipient) {
            $this->checkDuplicatedHeaderParameters($sharedHeader, $recipient->getHeader());
        }
        $clone = clone $this;
        $clone->sharedHeader = $sharedHeader;

        return $clone;
    }

    /**
     * Adds a recipient to the JWE to build.
     *
     * @return JWEBuilder
     */
    public function addRecipient(JWK $recipientKey, array $recipientHeader = []): self
    {
        $this->checkDuplicatedHeaderParameters($this->sharedProtectedHeader, $recipientHeader);
        $this->checkDuplicatedHeaderParameters($this->sharedHeader, $recipientHeader);
        $clone = clone $this;
        $completeHeader = \array_merge($clone->sharedHeader, $recipientHeader, $clone->sharedProtectedHeader);
        $clone->checkAndSetContentEncryptionAlgorithm($completeHeader);
        $keyEncryptionAlgorithm = $clone->getKeyEncryptionAlgorithm($completeHeader);
        if (null === $clone->keyManagementMode) {
            $clone->keyManagementMode = $keyEncryptionAlgorithm->getKeyManagementMode();
        } else {
            Assertion::true($clone->areKeyManagementModesCompatible($clone->keyManagementMode, $keyEncryptionAlgorithm->getKeyManagementMode()), 'Foreign key management mode forbidden.');
        }

        $compressionMethod = $clone->getCompressionMethod($completeHeader);
        if (null !== $compressionMethod) {
            if (null === $clone->compressionMethod) {
                $clone->compressionMethod = $compressionMethod;
            } elseif ($clone->compressionMethod->name() !== $compressionMethod->name()) {
                throw new \InvalidArgumentException('Incompatible compression method.');
            }
        }
        if (null === $compressionMethod && null !== $clone->compressionMethod) {
            throw new \InvalidArgumentException('Inconsistent compression method.');
        }
        $clone->checkKey($keyEncryptionAlgorithm, $recipientKey);
        $clone->recipients[] = [
            'key' => $recipientKey,
            'header' => $recipientHeader,
            'key_encryption_algorithm' => $keyEncryptionAlgorithm,
        ];

        return $clone;
    }

    /**
     * Builds the JWE.
     */
    public function build(): JWE
    {
        if (null === $this->payload) {
            throw new \LogicException('Payload not set.');
        }
        if (0 === \count($this->recipients)) {
            throw new \LogicException('No recipient.');
        }

        $additionalHeader = [];
        $cek = $this->determineCEK($additionalHeader);

        $recipients = [];
        foreach ($this->recipients as $recipient) {
            $recipient = $this->processRecipient($recipient, $cek, $additionalHeader);
            $recipients[] = $recipient;
        }

        if (0 !== \count($additionalHeader) && 1 === \count($this->recipients)) {
            $sharedProtectedHeader = \array_merge($additionalHeader, $this->sharedProtectedHeader);
        } else {
            $sharedProtectedHeader = $this->sharedProtectedHeader;
        }
        $encodedSharedProtectedHeader = 0 === \count($sharedProtectedHeader) ? '' : Base64Url::encode(JsonConverter::encode($sharedProtectedHeader));

        list($ciphertext, $iv, $tag) = $this->encryptJWE($cek, $encodedSharedProtectedHeader);

        return new JWE($ciphertext, $iv, $tag, $this->aad, $this->sharedHeader, $sharedProtectedHeader, $encodedSharedProtectedHeader, $recipients);
    }

    private function checkAndSetContentEncryptionAlgorithm(array $completeHeader): void
    {
        $contentEncryptionAlgorithm = $this->getContentEncryptionAlgorithm($completeHeader);
        if (null === $this->contentEncryptionAlgorithm) {
            $this->contentEncryptionAlgorithm = $contentEncryptionAlgorithm;
        } elseif ($contentEncryptionAlgorithm->name() !== $this->contentEncryptionAlgorithm->name()) {
            throw new \InvalidArgumentException('Inconsistent content encryption algorithm');
        }
    }

    private function processRecipient(array $recipient, string $cek, array &$additionalHeader): Recipient
    {
        $completeHeader = \array_merge($this->sharedHeader, $recipient['header'], $this->sharedProtectedHeader);
        $keyEncryptionAlgorithm = $recipient['key_encryption_algorithm'];
        Assertion::isInstanceOf($keyEncryptionAlgorithm, KeyEncryptionAlgorithm::class);
        $encryptedContentEncryptionKey = $this->getEncryptedKey($completeHeader, $cek, $keyEncryptionAlgorithm, $additionalHeader, $recipient['key']);
        $recipientHeader = $recipient['header'];
        if (0 !== \count($additionalHeader) && 1 !== \count($this->recipients)) {
            $recipientHeader = \array_merge($recipientHeader, $additionalHeader);
            $additionalHeader = [];
        }

        return new Recipient($recipientHeader, $encryptedContentEncryptionKey);
    }

    private function encryptJWE(string $cek, string $encodedSharedProtectedHeader): array
    {
        $tag = null;
        Assertion::isInstanceOf($this->contentEncryptionAlgorithm, ContentEncryptionAlgorithm::class);
        $iv_size = $this->contentEncryptionAlgorithm->getIVSize();
        $iv = $this->createIV($iv_size);
        $payload = $this->preparePayload();
        $ciphertext = $this->contentEncryptionAlgorithm->encryptContent($payload, $cek, $iv, $this->aad, $encodedSharedProtectedHeader, $tag);

        return [$ciphertext, $iv, $tag];
    }

    /**
     * @return string
     */
    private function preparePayload(): ?string
    {
        $prepared = $this->payload;
        if (null === $this->compressionMethod) {
            return $prepared;
        }

        return $this->compressionMethod->compress($prepared);
    }

    private function getEncryptedKey(array $completeHeader, string $cek, KeyEncryptionAlgorithm $keyEncryptionAlgorithm, array &$additionalHeader, JWK $recipientKey): ?string
    {
        if ($keyEncryptionAlgorithm instanceof KeyEncryption) {
            return $this->getEncryptedKeyFromKeyEncryptionAlgorithm($completeHeader, $cek, $keyEncryptionAlgorithm, $recipientKey, $additionalHeader);
        }
        if ($keyEncryptionAlgorithm instanceof KeyWrapping) {
            return $this->getEncryptedKeyFromKeyWrappingAlgorithm($completeHeader, $cek, $keyEncryptionAlgorithm, $recipientKey, $additionalHeader);
        }
        if ($keyEncryptionAlgorithm instanceof KeyAgreementWithKeyWrapping) {
            return $this->getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm($completeHeader, $cek, $keyEncryptionAlgorithm, $additionalHeader, $recipientKey);
        }
        if ($keyEncryptionAlgorithm instanceof KeyAgreement) {
            return null;
        }
        if ($keyEncryptionAlgorithm instanceof DirectEncryption) {
            return null;
        }

        throw new \InvalidArgumentException('Unsupported key encryption algorithm.');
    }

    private function getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm(array $completeHeader, string $cek, KeyAgreementWithKeyWrapping $keyEncryptionAlgorithm, array &$additionalHeader, JWK $recipientKey): string
    {
        Assertion::notNull($this->contentEncryptionAlgorithm);

        return $keyEncryptionAlgorithm->wrapAgreementKey($recipientKey, $cek, $this->contentEncryptionAlgorithm->getCEKSize(), $completeHeader, $additionalHeader);
    }

    private function getEncryptedKeyFromKeyEncryptionAlgorithm(array $completeHeader, string $cek, KeyEncryption $keyEncryptionAlgorithm, JWK $recipientKey, array &$additionalHeader): string
    {
        return $keyEncryptionAlgorithm->encryptKey($recipientKey, $cek, $completeHeader, $additionalHeader);
    }

    private function getEncryptedKeyFromKeyWrappingAlgorithm(array $completeHeader, string $cek, KeyWrapping $keyEncryptionAlgorithm, JWK $recipientKey, array &$additionalHeader): string
    {
        return $keyEncryptionAlgorithm->wrapKey($recipientKey, $cek, $completeHeader, $additionalHeader);
    }

    private function checkKey(KeyEncryptionAlgorithm $keyEncryptionAlgorithm, JWK $recipientKey): void
    {
        Assertion::notNull($this->contentEncryptionAlgorithm);
        KeyChecker::checkKeyUsage($recipientKey, 'encryption');
        if ('dir' !== $keyEncryptionAlgorithm->name()) {
            KeyChecker::checkKeyAlgorithm($recipientKey, $keyEncryptionAlgorithm->name());
        } else {
            KeyChecker::checkKeyAlgorithm($recipientKey, $this->contentEncryptionAlgorithm->name());
        }
    }

    private function determineCEK(array &$additionalHeader): string
    {
        Assertion::notNull($this->contentEncryptionAlgorithm);
        switch ($this->keyManagementMode) {
            case KeyEncryption::MODE_ENCRYPT:
            case KeyEncryption::MODE_WRAP:
                return $this->createCEK($this->contentEncryptionAlgorithm->getCEKSize());
            case KeyEncryption::MODE_AGREEMENT:
                if (1 !== \count($this->recipients)) {
                    throw new \LogicException('Unable to encrypt for multiple recipients using key agreement algorithms.');
                }
                /** @var JWK $key */
                $key = $this->recipients[0]['key'];
                $algorithm = $this->recipients[0]['key_encryption_algorithm'];
                Assertion::isInstanceOf($algorithm, KeyAgreement::class);
                $completeHeader = \array_merge($this->sharedHeader, $this->recipients[0]['header'], $this->sharedProtectedHeader);

                return $algorithm->getAgreementKey($this->contentEncryptionAlgorithm->getCEKSize(), $this->contentEncryptionAlgorithm->name(), $key, $completeHeader, $additionalHeader);
            case KeyEncryption::MODE_DIRECT:
                if (1 !== \count($this->recipients)) {
                    throw new \LogicException('Unable to encrypt for multiple recipients using key agreement algorithms.');
                }
                /** @var JWK $key */
                $key = $this->recipients[0]['key'];
                if ('oct' !== $key->get('kty')) {
                    throw new \RuntimeException('Wrong key type.');
                }

                return Base64Url::decode($key->get('k'));
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported key management mode "%s".', $this->keyManagementMode));
        }
    }

    private function getCompressionMethod(array $completeHeader): ?CompressionMethod
    {
        if (!\array_key_exists('zip', $completeHeader)) {
            return null;
        }

        return $this->compressionManager->get($completeHeader['zip']);
    }

    private function areKeyManagementModesCompatible(string $current, string $new): bool
    {
        $agree = KeyEncryptionAlgorithm::MODE_AGREEMENT;
        $dir = KeyEncryptionAlgorithm::MODE_DIRECT;
        $enc = KeyEncryptionAlgorithm::MODE_ENCRYPT;
        $wrap = KeyEncryptionAlgorithm::MODE_WRAP;
        $supportedKeyManagementModeCombinations = [$enc.$enc => true, $enc.$wrap => true, $wrap.$enc => true, $wrap.$wrap => true, $agree.$agree => false, $agree.$dir => false, $agree.$enc => false, $agree.$wrap => false, $dir.$agree => false, $dir.$dir => false, $dir.$enc => false, $dir.$wrap => false, $enc.$agree => false, $enc.$dir => false, $wrap.$agree => false, $wrap.$dir => false];

        if (\array_key_exists($current.$new, $supportedKeyManagementModeCombinations)) {
            return $supportedKeyManagementModeCombinations[$current.$new];
        }

        return false;
    }

    private function createCEK(int $size): string
    {
        return \random_bytes($size / 8);
    }

    private function createIV(int $size): string
    {
        return \random_bytes($size / 8);
    }

    private function getKeyEncryptionAlgorithm(array $completeHeader): KeyEncryptionAlgorithm
    {
        Assertion::keyExists($completeHeader, 'alg', 'Parameter "alg" is missing.');
        $keyEncryptionAlgorithm = $this->keyEncryptionAlgorithmManager->get($completeHeader['alg']);
        Assertion::isInstanceOf($keyEncryptionAlgorithm, KeyEncryptionAlgorithm::class, sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $completeHeader['alg']));

        return $keyEncryptionAlgorithm;
    }

    private function getContentEncryptionAlgorithm(array $completeHeader): ContentEncryptionAlgorithm
    {
        Assertion::keyExists($completeHeader, 'enc', 'Parameter "enc" is missing.');
        $contentEncryptionAlgorithm = $this->contentEncryptionAlgorithmManager->get($completeHeader['enc']);
        Assertion::isInstanceOf($contentEncryptionAlgorithm, ContentEncryptionAlgorithm::class, sprintf('The content encryption algorithm "%s" is not supported or not a content encryption algorithm instance.', $completeHeader['enc']));

        return $contentEncryptionAlgorithm;
    }

    private function checkDuplicatedHeaderParameters(array $header1, array $header2): void
    {
        $inter = \array_intersect_key($header1, $header2);
        Assertion::noContent($inter, sprintf('The header contains duplicated entries: %s.', \implode(', ', \array_keys($inter))));
    }
}

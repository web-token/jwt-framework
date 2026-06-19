<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use InvalidArgumentException;
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
use Throwable;
use function is_string;
use function sprintf;
use function strlen;

class JWEDecrypter
{
    private readonly AlgorithmManager $keyEncryptionAlgorithmManager;

    private readonly AlgorithmManager $contentEncryptionAlgorithmManager;

    public function __construct(AlgorithmManager $algorithmManager)
    {
        $keyEncryptionAlgorithms = [];
        $contentEncryptionAlgorithms = [];
        foreach ($algorithmManager->all() as $key => $algorithm) {
            if ($algorithm instanceof KeyEncryptionAlgorithm) {
                $keyEncryptionAlgorithms[$key] = $algorithm;
            }
            if ($algorithm instanceof ContentEncryptionAlgorithm) {
                $contentEncryptionAlgorithms[$key] = $algorithm;
            }
        }
        $this->keyEncryptionAlgorithmManager = new AlgorithmManager($keyEncryptionAlgorithms);
        $this->contentEncryptionAlgorithmManager = new AlgorithmManager($contentEncryptionAlgorithms);
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
     * This method will try to decrypt the given JWE and recipient using a JWK.
     *
     * @param JWE $jwe A JWE object to decrypt
     * @param JWK $jwk The key used to decrypt the input
     * @param int $recipient The recipient used to decrypt the token
     */
    public function decryptUsingKey(JWE &$jwe, JWK $jwk, int $recipient, ?JWK $senderKey = null): bool
    {
        $jwkset = new JWKSet([$jwk]);

        return $this->decryptUsingKeySet($jwe, $jwkset, $recipient, $senderKey);
    }

    /**
     * This method will try to decrypt the given JWE and recipient using a JWKSet.
     *
     * @param JWE $jwe A JWE object to decrypt
     * @param JWKSet $jwkset The key set used to decrypt the input
     * @param JWK $jwk The key used to decrypt the token in case of success
     * @param int $recipient The recipient used to decrypt the token in case of success
     */
    public function decryptUsingKeySet(
        JWE &$jwe,
        JWKSet $jwkset,
        int $recipient,
        ?JWK &$jwk = null,
        ?JWK $senderKey = null
    ): bool {
        if ($jwkset->count() === 0) {
            throw new InvalidArgumentException('No key in the key set.');
        }
        if ($jwe->getPayload() !== null) {
            return true;
        }
        if ($jwe->countRecipients() === 0) {
            throw new InvalidArgumentException('The JWE does not contain any recipient.');
        }

        $plaintext = $this->decryptRecipientKey($jwe, $jwkset, $recipient, $jwk, $senderKey);
        if ($plaintext !== null) {
            $jwe = $jwe->withPayload($plaintext);

            return true;
        }

        return false;
    }

    private function decryptRecipientKey(
        JWE $jwe,
        JWKSet $jwkset,
        int $i,
        ?JWK &$successJwk = null,
        ?JWK $senderKey = null
    ): ?string {
        $recipient = $jwe->getRecipient($i);
        $completeHeader = array_merge(
            $jwe->getSharedProtectedHeader(),
            $jwe->getSharedHeader(),
            $recipient->getHeader()
        );
        $this->checkCompleteHeader($completeHeader);

        // RFC 7516 §4.1.1 (alg) and §4.1.2 (enc) require both parameters to be
        // integrity-protected. Reading them from the merged $completeHeader allows
        // an attacker to override either value via an unprotected header field.
        $sharedProtectedHeader = $jwe->getSharedProtectedHeader();
        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($sharedProtectedHeader);
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($sharedProtectedHeader);

        $this->checkIvSize($jwe->getIV(), $content_encryption_algorithm->getIVSize());

        foreach ($jwkset as $recipientKey) {
            try {
                KeyChecker::checkKeyUsage($recipientKey, 'decryption');
                if ($key_encryption_algorithm->name() !== 'dir') {
                    KeyChecker::checkKeyAlgorithm($recipientKey, $key_encryption_algorithm->name());
                } else {
                    KeyChecker::checkKeyAlgorithm($recipientKey, $content_encryption_algorithm->name());
                }
                $cek = $this->decryptCEK(
                    $key_encryption_algorithm,
                    $content_encryption_algorithm,
                    $recipientKey,
                    $senderKey,
                    $recipient,
                    $completeHeader
                );
                $this->checkCekSize($cek, $key_encryption_algorithm, $content_encryption_algorithm);
                $payload = $this->decryptPayload($jwe, $cek, $content_encryption_algorithm);
                $successJwk = $recipientKey;

                return $payload;
            } catch (Throwable) {
                //We do nothing, we continue with other keys
                continue;
            }
        }

        return null;
    }

    private function checkCekSize(
        string $cek,
        KeyEncryptionAlgorithm $keyEncryptionAlgorithm,
        ContentEncryptionAlgorithm $algorithm
    ): void {
        if ($keyEncryptionAlgorithm instanceof DirectEncryption || $keyEncryptionAlgorithm instanceof KeyAgreement) {
            return;
        }
        if (strlen($cek) * 8 !== $algorithm->getCEKSize()) {
            throw new InvalidArgumentException('Invalid CEK size');
        }
    }

    private function checkIvSize(?string $iv, int $requiredIvSize): void
    {
        if ($iv === null && $requiredIvSize !== 0) {
            throw new InvalidArgumentException('Invalid IV size');
        }
        if (is_string($iv) && strlen($iv) !== $requiredIvSize / 8) {
            throw new InvalidArgumentException('Invalid IV size');
        }
    }

    private function decryptCEK(
        Algorithm $key_encryption_algorithm,
        ContentEncryptionAlgorithm $content_encryption_algorithm,
        JWK $recipientKey,
        ?JWK $senderKey,
        Recipient $recipient,
        array $completeHeader
    ): string {
        if ($key_encryption_algorithm instanceof DirectEncryption) {
            return $key_encryption_algorithm->getCEK($recipientKey);
        }
        if ($key_encryption_algorithm instanceof KeyAgreement) {
            return $key_encryption_algorithm->getAgreementKey(
                $content_encryption_algorithm->getCEKSize(),
                $content_encryption_algorithm->name(),
                $recipientKey,
                $senderKey,
                $completeHeader
            );
        }
        if ($key_encryption_algorithm instanceof KeyAgreementWithKeyWrapping) {
            return $key_encryption_algorithm->unwrapAgreementKey(
                $recipientKey,
                $senderKey,
                $recipient->getEncryptedKey() ?? '',
                $content_encryption_algorithm->getCEKSize(),
                $completeHeader
            );
        }
        if ($key_encryption_algorithm instanceof KeyEncryption) {
            return $key_encryption_algorithm->decryptKey(
                $recipientKey,
                $recipient->getEncryptedKey() ?? '',
                $completeHeader
            );
        }
        if ($key_encryption_algorithm instanceof KeyWrapping) {
            return $key_encryption_algorithm->unwrapKey(
                $recipientKey,
                $recipient->getEncryptedKey() ?? '',
                $completeHeader
            );
        }

        throw new InvalidArgumentException('Unsupported CEK generation');
    }

    private function decryptPayload(
        JWE $jwe,
        string $cek,
        ContentEncryptionAlgorithm $content_encryption_algorithm,
    ): string {
        return $content_encryption_algorithm->decryptContent(
            $jwe->getCiphertext() ?? '',
            $cek,
            $jwe->getIV() ?? '',
            $jwe->getAAD(),
            $jwe->getEncodedSharedProtectedHeader(),
            $jwe->getTag() ?? ''
        );
    }

    private function checkCompleteHeader(array $completeHeaders): void
    {
        foreach (['enc', 'alg'] as $key) {
            if (! isset($completeHeaders[$key])) {
                throw new InvalidArgumentException(sprintf("Parameter '%s' is missing.", $key));
            }
        }
    }

    private function getKeyEncryptionAlgorithm(array $protectedHeader): KeyEncryptionAlgorithm
    {
        $alg = $protectedHeader['alg'] ?? null;
        if (! is_string($alg) || $alg === '') {
            throw new InvalidArgumentException(
                'The "alg" parameter must be a non-empty string in the protected header (RFC 7516 §4.1.1).'
            );
        }
        $key_encryption_algorithm = $this->keyEncryptionAlgorithmManager->get($alg);
        if (! $key_encryption_algorithm instanceof KeyEncryptionAlgorithm) {
            throw new InvalidArgumentException(sprintf(
                'The key encryption algorithm "%s" is not supported or does not implement KeyEncryptionAlgorithm interface.',
                $alg
            ));
        }

        return $key_encryption_algorithm;
    }

    private function getContentEncryptionAlgorithm(array $protectedHeader): ContentEncryptionAlgorithm
    {
        $enc = $protectedHeader['enc'] ?? null;
        if (! is_string($enc) || $enc === '') {
            throw new InvalidArgumentException(
                'The "enc" parameter must be a non-empty string in the protected header (RFC 7516 §4.1.2).'
            );
        }
        $content_encryption_algorithm = $this->contentEncryptionAlgorithmManager->get($enc);
        if (! $content_encryption_algorithm instanceof ContentEncryptionAlgorithm) {
            throw new InvalidArgumentException(sprintf(
                'The content encryption algorithm "%s" is not supported or does not implement the ContentEncryption interface.',
                $enc
            ));
        }

        return $content_encryption_algorithm;
    }
}

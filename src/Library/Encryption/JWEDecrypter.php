<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidKeySetException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\HeaderParameterChecker;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryption\DirectEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreement;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementWithKeyWrapping;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrapping;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Encryption\Util\EncryptionAlgorithmManagers;
use Throwable;
use function func_num_args;
use function is_callable;
use function is_string;
use function sprintf;
use function strlen;
use function trigger_deprecation;

/**
 * @final The class will be final in 5.0.0: implement JWEDecrypterInterface and decorate the service instead of
 * extending it.
 */
class JWEDecrypter implements JWEDecrypterInterface
{
    private readonly AlgorithmManager $keyEncryptionAlgorithmManager;

    private readonly AlgorithmManager $contentEncryptionAlgorithmManager;

    public function __construct(AlgorithmManager $algorithmManager)
    {
        InheritanceChecker::warnIfExtended(static::class, self::class, JWEDecrypterInterface::class);
        $managers = EncryptionAlgorithmManagers::split($algorithmManager, static::class);
        $this->keyEncryptionAlgorithmManager = $managers->keyEncryption;
        $this->contentEncryptionAlgorithmManager = $managers->contentEncryption;
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
     * @param int $recipient The index of the recipient to decrypt
     * @param JWK|null $senderKey The sender key, when the key management algorithm is a static key agreement
     *
     * @deprecated since 4.3.0, use "decrypt()" instead. Will be removed in 5.0.0.
     */
    public function decryptUsingKey(JWE &$jwe, JWK $jwk, int $recipient, ?JWK $senderKey = null): bool
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::decryptUsingKey()" is deprecated and will be removed in 5.0.0. Please use "%s::decrypt()" instead: it returns a "%s" object that carries the decrypted JWE instead of replacing the variable of the caller.',
            self::class,
            self::class,
            DecryptionResult::class
        );
        $jwkset = new JWKSet([$jwk]);
        $successJwk = null;

        return $this->decryptUsingKeySet($jwe, $jwkset, $recipient, $successJwk, $senderKey);
    }

    /**
     * This method will try to decrypt the given JWE and recipient using a JWKSet.
     *
     * A callable is accepted as an additional argument to observe the failures met while trying the keys. That argument
     * is not part of the signature and is read with func_num_args()/func_get_arg(5), so that the objects decorating
     * this one remain compatible.
     *
     * @param JWE $jwe A JWE object to decrypt
     * @param JWKSet $jwkset The key set used to decrypt the input
     * @param int $recipient The index of the recipient to decrypt
     * @param JWK|null $jwk The key used to decrypt the token in case of success
     * @param JWK|null $senderKey The sender key, when the key management algorithm is a static key agreement
     *
     * @deprecated since 4.3.0, use "decrypt()" instead. Will be removed in 5.0.0.
     */
    public function decryptUsingKeySet(
        JWE &$jwe,
        JWKSet $jwkset,
        int $recipient,
        ?JWK &$jwk = null,
        ?JWK $senderKey = null
    ): bool {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::decryptUsingKeySet()" is deprecated and will be removed in 5.0.0. Please use "%s::decrypt()" instead: it returns a "%s" object that carries the decrypted JWE and the key instead of replacing the variables of the caller.',
            self::class,
            self::class,
            DecryptionResult::class
        );
        $onError = func_num_args() >= 6 ? func_get_arg(5) : null;
        if (! is_callable($onError)) {
            $onError = null;
        }
        $result = $this->decrypt($jwe, $jwkset, $recipient, $senderKey, $onError);
        if (! $result->isDecrypted()) {
            return false;
        }
        $jwe = $result->getJwe();
        $successJwk = $result->getKey();
        if ($successJwk !== null) {
            $jwk = $successJwk;
        }

        return true;
    }

    /**
     * This method will try to decrypt the given recipient of the given JWE using a key or a key set. The decrypted JWE
     * and the key that decrypted it are carried by the returned result: JWE objects are immutable, so the JWE given to
     * this method is left untouched.
     *
     * A key that cannot be used, or that does not decrypt the recipient, does not abort the decryption: the next key of
     * the key set is tried and the reason of the failure is otherwise lost. The optional callable is called with every
     * discarded Throwable, so that those failures can be observed.
     *
     * @param JWE $jwe A JWE object to decrypt
     * @param JWK|JWKSet $keys The recipient will be decrypted using that key or the keys in that key set
     * @param int $recipientIndex The index of the recipient to decrypt
     * @param JWK|null $senderKey The sender key, when the key management algorithm is a static key agreement
     * @param (callable(Throwable): void)|null $onError Called with every failure met while trying the keys
     */
    public function decrypt(
        JWE $jwe,
        JWK|JWKSet $keys,
        int $recipientIndex,
        ?JWK $senderKey = null,
        ?callable $onError = null
    ): DecryptionResult {
        $jwkset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        if ($jwkset->count() === 0) {
            throw new InvalidKeySetException('No key in the key set.');
        }
        if ($jwe->getPayload() !== null) {
            return DecryptionResult::success($jwe, $recipientIndex, null);
        }
        if ($jwe->countRecipients() === 0) {
            throw new InvalidArgumentException('The JWE does not contain any recipient.');
        }

        return $this->decryptRecipientKey($jwe, $jwkset, $recipientIndex, $senderKey, $onError)
            ?? DecryptionResult::failure($jwe, $recipientIndex);
    }

    /**
     * The header parameter names of the shared protected header, the shared unprotected header and the
     * per-recipient header must be disjoint (RFC 7516 section 7.2.1), as enforced by the JWEBuilder when the
     * token is created. Otherwise an unprotected parameter is able to redefine a protected one. The headers
     * are then merged in the same order as the JWEBuilder does, so that the protected header always wins.
     *
     * The shared unprotected header is never a valid source for "alg" and "enc": it is not covered by the
     * AAD and, unlike the per-recipient header, nothing requires those parameters to be located there.
     *
     * @param (callable(Throwable): void)|null $onError
     */
    private function decryptRecipientKey(
        JWE $jwe,
        JWKSet $jwkset,
        int $i,
        ?JWK $senderKey = null,
        ?callable $onError = null
    ): ?DecryptionResult {
        $recipient = $jwe->getRecipient($i);
        $sharedProtectedHeader = $jwe->getSharedProtectedHeader();
        $sharedHeader = $jwe->getSharedHeader();
        $recipientHeader = $recipient->getHeader();

        HeaderParameterChecker::checkDuplicates($sharedProtectedHeader, $sharedHeader);
        HeaderParameterChecker::checkDuplicates($sharedProtectedHeader, $recipientHeader);
        HeaderParameterChecker::checkDuplicates($sharedHeader, $recipientHeader);

        $completeHeader = array_merge($sharedHeader, $recipientHeader, $sharedProtectedHeader);
        $this->checkCompleteHeader($completeHeader);

        $protectedAndRecipientHeader = array_merge($recipientHeader, $sharedProtectedHeader);
        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($protectedAndRecipientHeader);
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($protectedAndRecipientHeader);

        $this->checkIvSize($jwe->getIV(), $content_encryption_algorithm->getIVSize());

        foreach ($jwkset->all() as $recipientKey) {
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

                return DecryptionResult::success($jwe->withPayload($payload), $i, $recipientKey);
            } catch (Throwable $throwable) {
                if ($onError !== null) {
                    $onError($throwable);
                }

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
        // The size of the key expected by the content encryption algorithm is passed as an additional
        // argument. It is not part of the interfaces yet (it will be in 5.0.0): implementations that do not
        // expect it simply ignore it, the others read it with func_num_args()/func_get_arg(3).
        if ($key_encryption_algorithm instanceof KeyEncryption) {
            // @phpstan-ignore arguments.count (the fourth argument will be part of the interface in 5.0.0)
            return $key_encryption_algorithm->decryptKey(
                $recipientKey,
                $recipient->getEncryptedKey() ?? '',
                $completeHeader,
                $content_encryption_algorithm->getCEKSize()
            );
        }
        if ($key_encryption_algorithm instanceof KeyWrapping) {
            // @phpstan-ignore arguments.count (the fourth argument will be part of the interface in 5.0.0)
            return $key_encryption_algorithm->unwrapKey(
                $recipientKey,
                $recipient->getEncryptedKey() ?? '',
                $completeHeader,
                $content_encryption_algorithm->getCEKSize()
            );
        }

        throw new UnsupportedAlgorithmException('Unsupported CEK generation');
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
                throw new InvalidHeaderParameterException(sprintf("Parameter '%s' is missing.", $key));
            }
        }
    }

    private function getKeyEncryptionAlgorithm(array $header): KeyEncryptionAlgorithm
    {
        $alg = $header['alg'] ?? null;
        if (! is_string($alg) || $alg === '') {
            throw new InvalidArgumentException(
                'The "alg" parameter must be a non-empty string set in the protected header or in the recipient header.'
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

    private function getContentEncryptionAlgorithm(array $header): ContentEncryptionAlgorithm
    {
        $enc = $header['enc'] ?? null;
        if (! is_string($enc) || $enc === '') {
            throw new InvalidArgumentException(
                'The "enc" parameter must be a non-empty string set in the protected header or in the recipient header.'
            );
        }
        $content_encryption_algorithm = $this->contentEncryptionAlgorithmManager->get($enc);
        if (! $content_encryption_algorithm instanceof ContentEncryptionAlgorithm) {
            throw new UnsupportedAlgorithmException(sprintf(
                'The content encryption algorithm "%s" is not supported or does not implement the ContentEncryption interface.',
                $enc
            ));
        }

        return $content_encryption_algorithm;
    }
}

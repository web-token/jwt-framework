<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\Exception\MissingPayloadLogicException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\HeaderParameterChecker;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryption\DirectEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreement;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementWithKeyWrapping;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrapping;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Encryption\Util\EncryptionAlgorithmManagers;
use function array_key_exists;
use function count;
use function intdiv;
use function is_string;
use function sprintf;
use function trigger_deprecation;

/**
 * Builds a JWE.
 *
 * The builder is immutable: every method that sets a header, a payload or adds a recipient returns a new
 * object and never modifies the receiver, so that a builder registered as a shared service cannot be
 * poisoned by a previous build. The key encryption and content encryption algorithms are read from the
 * complete header of each recipient, which is only known once every shared header is set: they are resolved
 * by build(), together with all the checks that involve more than one recipient. The order of the calls is
 * therefore irrelevant.
 *
 * @final The class will be final in 5.0.0: implement JWEBuilderInterface and decorate the service instead of
 * extending it.
 */
class JWEBuilder implements JWEBuilderInterface
{
    protected ?JWK $senderKey = null;

    protected ?string $payload = null;

    protected ?string $aad = null;

    /**
     * @var list<RecipientSpec>
     */
    protected array $recipients = [];

    /**
     * @var array<string, mixed>
     */
    protected array $sharedProtectedHeader = [];

    /**
     * @var array<string, mixed>
     */
    protected array $sharedHeader = [];

    private readonly AlgorithmManager $keyEncryptionAlgorithmManager;

    private readonly AlgorithmManager $contentEncryptionAlgorithmManager;

    public function __construct(AlgorithmManager $algorithmManager)
    {
        InheritanceChecker::warnIfExtended(static::class, self::class, JWEBuilderInterface::class);
        $managers = EncryptionAlgorithmManagers::split($algorithmManager, static::class);
        $this->keyEncryptionAlgorithmManager = $managers->keyEncryption;
        $this->contentEncryptionAlgorithmManager = $managers->contentEncryption;
    }

    /**
     * Reset the current data.
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. The builder is immutable, hence there is no state
     *             to reset: remove the call, or build a new object with "new JWEBuilder($algorithmManager)".
     */
    public function create(): self
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::create()" is deprecated and will be removed in 5.0.0. The builder is immutable, hence there is no state to reset: remove the call, or build a new object with "new %s($algorithmManager)".',
            self::class,
            self::class
        );

        $clone = clone $this;
        $clone->senderKey = null;
        $clone->payload = null;
        $clone->aad = null;
        $clone->recipients = [];
        $clone->sharedProtectedHeader = [];
        $clone->sharedHeader = [];

        return $clone;
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
     * Set the payload of the JWE to build.
     */
    public function withPayload(string $payload): self
    {
        $clone = clone $this;
        $clone->payload = $payload;

        return $clone;
    }

    /**
     * Set the Additional Authenticated Data of the JWE to build.
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
     * @param array<string, mixed> $sharedProtectedHeader
     */
    public function withSharedProtectedHeader(array $sharedProtectedHeader): self
    {
        $clone = clone $this;
        $clone->sharedProtectedHeader = $sharedProtectedHeader;

        return $clone;
    }

    /**
     * Set the shared header of the JWE to build.
     *
     * @param array<string, mixed> $sharedHeader
     */
    public function withSharedHeader(array $sharedHeader): self
    {
        $clone = clone $this;
        $clone->sharedHeader = $sharedHeader;

        return $clone;
    }

    /**
     * Adds a recipient to the JWE to build.
     *
     * @param array<string, mixed> $recipientHeader
     */
    public function addRecipient(JWK $recipientKey, array $recipientHeader = []): self
    {
        $clone = clone $this;
        $clone->recipients[] = new RecipientSpec($recipientKey, $recipientHeader);

        return $clone;
    }

    /**
     * Set the sender JWK to be used instead of the internal generated JWK.
     *
     * The sender key does not add a recipient: it takes no part in the key management mode compatibility
     * check, otherwise a static key agreement algorithm such as ECDH-SS would be rejected as a foreign key
     * management mode. The key itself is verified by build(), where the recipients and the content
     * encryption algorithm are known whatever the call order is.
     */
    public function withSenderKey(JWK $senderKey): self
    {
        $clone = clone $this;
        $clone->senderKey = $senderKey;

        return $clone;
    }

    /**
     * Builds the JWE.
     */
    public function build(): JWE
    {
        if ($this->payload === null) {
            throw new MissingPayloadLogicException('Payload not set.');
        }
        if (count($this->recipients) === 0) {
            throw new LogicException('No recipient.');
        }
        $this->checkDuplicatedHeaderParametersOfAllRecipients();
        $contentEncryptionAlgorithm = $this->resolveContentEncryptionAlgorithm();
        $keyEncryptionAlgorithms = $this->resolveKeyEncryptionAlgorithms();
        $keyManagementMode = $this->resolveKeyManagementMode($keyEncryptionAlgorithms);
        $this->checkKeys($keyEncryptionAlgorithms, $contentEncryptionAlgorithm);

        $additionalHeader = [];
        $cek = $this->determineCEK(
            $keyManagementMode,
            $keyEncryptionAlgorithms,
            $contentEncryptionAlgorithm,
            $additionalHeader
        );

        $recipients = [];
        foreach ($this->recipients as $index => $recipient) {
            $recipients[] = $this->processRecipient(
                $recipient,
                $keyEncryptionAlgorithms[$index],
                $contentEncryptionAlgorithm,
                $cek,
                $additionalHeader
            );
        }

        if (count($additionalHeader) !== 0 && count($this->recipients) === 1) {
            $sharedProtectedHeader = array_merge($additionalHeader, $this->sharedProtectedHeader);
        } else {
            $sharedProtectedHeader = $this->sharedProtectedHeader;
        }
        $encodedSharedProtectedHeader = count($sharedProtectedHeader) === 0 ? '' : Base64UrlSafe::encodeUnpadded(
            JsonConverter::encode($sharedProtectedHeader)
        );

        [$ciphertext, $iv, $tag] = $this->encryptJWE(
            $contentEncryptionAlgorithm,
            $cek,
            $encodedSharedProtectedHeader
        );

        return new JWE(
            $ciphertext,
            $iv,
            $tag,
            $this->aad,
            $this->sharedHeader,
            $sharedProtectedHeader,
            $encodedSharedProtectedHeader,
            $recipients
        );
    }

    /**
     * Returns the recipients in the array shape the builder used before 4.3.0.
     *
     * The key encryption algorithm is only present when the headers of the recipient carry a supported "alg"
     * parameter. It was always present before 4.3.0, where a recipient without a resolvable algorithm was
     * rejected by addRecipient() instead of build().
     *
     * @internal
     * @return array<array{
     *     key: JWK,
     *     header: array<string, mixed>,
     *     key_encryption_algorithm?: KeyEncryptionAlgorithm
     * }>
     */
    protected function getRecipientsAsArray(): array
    {
        $recipients = [];
        foreach ($this->recipients as $recipient) {
            $entry = [
                'key' => $recipient->key,
                'header' => $recipient->header,
            ];
            $alg = $this->getCompleteHeader($recipient)['alg'] ?? null;
            if (is_string($alg) && $this->keyEncryptionAlgorithmManager->has($alg)) {
                $algorithm = $this->keyEncryptionAlgorithmManager->get($alg);
                if ($algorithm instanceof KeyEncryptionAlgorithm) {
                    $entry['key_encryption_algorithm'] = $algorithm;
                }
            }
            $recipients[] = $entry;
        }

        return $recipients;
    }

    /**
     * Returns the header of a recipient merged with the shared headers.
     *
     * @return array<string, mixed>
     */
    private function getCompleteHeader(RecipientSpec $recipient): array
    {
        return array_merge($this->sharedHeader, $recipient->header, $this->sharedProtectedHeader);
    }

    /**
     * The header parameter names of the shared protected header, of the shared header and of every recipient
     * header must be disjoint (RFC 7516 section 7.2.1).
     */
    private function checkDuplicatedHeaderParametersOfAllRecipients(): void
    {
        HeaderParameterChecker::checkDuplicates($this->sharedProtectedHeader, $this->sharedHeader);
        foreach ($this->recipients as $recipient) {
            HeaderParameterChecker::checkDuplicates($this->sharedProtectedHeader, $recipient->header);
            HeaderParameterChecker::checkDuplicates($this->sharedHeader, $recipient->header);
        }
    }

    /**
     * All the recipients share the same content encryption algorithm: the content is encrypted once.
     */
    private function resolveContentEncryptionAlgorithm(): ContentEncryptionAlgorithm
    {
        $contentEncryptionAlgorithm = null;
        foreach ($this->recipients as $recipient) {
            $current = $this->getContentEncryptionAlgorithm($this->getCompleteHeader($recipient));
            if ($contentEncryptionAlgorithm === null) {
                $contentEncryptionAlgorithm = $current;

                continue;
            }
            if ($current->name() !== $contentEncryptionAlgorithm->name()) {
                throw new UnsupportedAlgorithmException('Inconsistent content encryption algorithm');
            }
        }
        if ($contentEncryptionAlgorithm === null) {
            throw new UnsupportedAlgorithmException('Invalid content encryption algorithm');
        }

        return $contentEncryptionAlgorithm;
    }

    /**
     * @return list<KeyEncryptionAlgorithm>
     */
    private function resolveKeyEncryptionAlgorithms(): array
    {
        $keyEncryptionAlgorithms = [];
        foreach ($this->recipients as $recipient) {
            $keyEncryptionAlgorithms[] = $this->getKeyEncryptionAlgorithm($this->getCompleteHeader($recipient));
        }

        return $keyEncryptionAlgorithms;
    }

    /**
     * The key management mode of the first recipient is the one of the JWE: the algorithms of the other
     * recipients are only accepted when they can be combined with it.
     *
     * @param list<KeyEncryptionAlgorithm> $keyEncryptionAlgorithms
     */
    private function resolveKeyManagementMode(array $keyEncryptionAlgorithms): string
    {
        $keyManagementMode = null;
        foreach ($keyEncryptionAlgorithms as $keyEncryptionAlgorithm) {
            if ($keyManagementMode === null) {
                $keyManagementMode = $keyEncryptionAlgorithm->getKeyManagementMode();

                continue;
            }
            if (! $this->areKeyManagementModesCompatible(
                $keyManagementMode,
                $keyEncryptionAlgorithm->getKeyManagementMode()
            )) {
                throw new InvalidArgumentException('Foreign key management mode forbidden.');
            }
        }
        if ($keyManagementMode === null) {
            throw new LogicException('No recipient.');
        }

        return $keyManagementMode;
    }

    /**
     * The sender key is shared by all the recipients: it is verified against the key encryption algorithm of
     * each of them. Nothing is done for it when no sender key is set.
     *
     * @param list<KeyEncryptionAlgorithm> $keyEncryptionAlgorithms
     */
    private function checkKeys(
        array $keyEncryptionAlgorithms,
        ContentEncryptionAlgorithm $contentEncryptionAlgorithm
    ): void {
        foreach ($this->recipients as $index => $recipient) {
            $this->checkKey($keyEncryptionAlgorithms[$index], $recipient->key, $contentEncryptionAlgorithm);
        }
        $senderKey = $this->senderKey;
        if ($senderKey === null) {
            return;
        }
        foreach ($keyEncryptionAlgorithms as $keyEncryptionAlgorithm) {
            $this->checkKey($keyEncryptionAlgorithm, $senderKey, $contentEncryptionAlgorithm);
        }
    }

    /**
     * The header parameters computed by the key encryption algorithm are added to the per-recipient header
     * when there is more than one recipient. Those already set in a shared header are filtered out: the
     * header parameter names of the three headers must be disjoint (RFC 7516 section 7.2.1), and a shared
     * value takes precedence, as it does with a single recipient.
     *
     * @param array<string, mixed> $additionalHeader
     */
    private function processRecipient(
        RecipientSpec $recipient,
        KeyEncryptionAlgorithm $keyEncryptionAlgorithm,
        ContentEncryptionAlgorithm $contentEncryptionAlgorithm,
        string $cek,
        array &$additionalHeader
    ): Recipient {
        $encryptedContentEncryptionKey = $this->getEncryptedKey(
            $this->getCompleteHeader($recipient),
            $cek,
            $keyEncryptionAlgorithm,
            $contentEncryptionAlgorithm,
            $additionalHeader,
            $recipient->key,
            $this->senderKey
        );
        $recipientHeader = $recipient->header;
        if (count($additionalHeader) !== 0 && count($this->recipients) !== 1) {
            $additionalHeader = array_diff_key($additionalHeader, $this->sharedProtectedHeader, $this->sharedHeader);
            $recipientHeader = array_merge($recipientHeader, $additionalHeader);
            $additionalHeader = [];
        }

        return new Recipient($recipientHeader, $encryptedContentEncryptionKey);
    }

    /**
     * @return array{string, string, string}
     */
    private function encryptJWE(
        ContentEncryptionAlgorithm $contentEncryptionAlgorithm,
        string $cek,
        string $encodedSharedProtectedHeader
    ): array {
        $iv_size = $contentEncryptionAlgorithm->getIVSize();
        $iv = $this->createIV($iv_size);
        $payload = $this->payload;
        $tag = null;
        $ciphertext = $contentEncryptionAlgorithm->encryptContent(
            $payload ?? '',
            $cek,
            $iv,
            $this->aad,
            $encodedSharedProtectedHeader,
            $tag
        );
        if ($tag === null) {
            throw new RuntimeException(sprintf(
                'The content encryption algorithm "%s" did not compute an authentication tag.',
                $contentEncryptionAlgorithm->name()
            ));
        }

        return [$ciphertext, $iv, $tag];
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    private function getEncryptedKey(
        array $completeHeader,
        string $cek,
        KeyEncryptionAlgorithm $keyEncryptionAlgorithm,
        ContentEncryptionAlgorithm $contentEncryptionAlgorithm,
        array &$additionalHeader,
        JWK $recipientKey,
        ?JWK $senderKey
    ): ?string {
        if ($keyEncryptionAlgorithm instanceof KeyEncryption) {
            return $this->getEncryptedKeyFromKeyEncryptionAlgorithm(
                $completeHeader,
                $cek,
                $keyEncryptionAlgorithm,
                $recipientKey,
                $additionalHeader
            );
        }
        if ($keyEncryptionAlgorithm instanceof KeyWrapping) {
            return $this->getEncryptedKeyFromKeyWrappingAlgorithm(
                $completeHeader,
                $cek,
                $keyEncryptionAlgorithm,
                $recipientKey,
                $additionalHeader
            );
        }
        if ($keyEncryptionAlgorithm instanceof KeyAgreementWithKeyWrapping) {
            return $this->getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm(
                $completeHeader,
                $cek,
                $keyEncryptionAlgorithm,
                $contentEncryptionAlgorithm,
                $additionalHeader,
                $recipientKey,
                $senderKey
            );
        }
        if ($keyEncryptionAlgorithm instanceof KeyAgreement) {
            return null;
        }
        if ($keyEncryptionAlgorithm instanceof DirectEncryption) {
            return null;
        }

        throw new UnsupportedAlgorithmException('Unsupported key encryption algorithm.');
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    private function getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm(
        array $completeHeader,
        string $cek,
        KeyAgreementWithKeyWrapping $keyEncryptionAlgorithm,
        ContentEncryptionAlgorithm $contentEncryptionAlgorithm,
        array &$additionalHeader,
        JWK $recipientKey,
        ?JWK $senderKey
    ): string {
        return $keyEncryptionAlgorithm->wrapAgreementKey(
            $recipientKey,
            $senderKey,
            $cek,
            $contentEncryptionAlgorithm->getCEKSize(),
            $completeHeader,
            $additionalHeader
        );
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    private function getEncryptedKeyFromKeyEncryptionAlgorithm(
        array $completeHeader,
        string $cek,
        KeyEncryption $keyEncryptionAlgorithm,
        JWK $recipientKey,
        array &$additionalHeader
    ): string {
        return $keyEncryptionAlgorithm->encryptKey($recipientKey, $cek, $completeHeader, $additionalHeader);
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    private function getEncryptedKeyFromKeyWrappingAlgorithm(
        array $completeHeader,
        string $cek,
        KeyWrapping $keyEncryptionAlgorithm,
        JWK $recipientKey,
        array &$additionalHeader
    ): string {
        return $keyEncryptionAlgorithm->wrapKey($recipientKey, $cek, $completeHeader, $additionalHeader);
    }

    private function checkKey(
        KeyEncryptionAlgorithm $keyEncryptionAlgorithm,
        JWK $recipientKey,
        ContentEncryptionAlgorithm $contentEncryptionAlgorithm
    ): void {
        KeyChecker::checkKeyUsage($recipientKey, 'encryption');
        if ($keyEncryptionAlgorithm->name() !== 'dir') {
            KeyChecker::checkKeyAlgorithm($recipientKey, $keyEncryptionAlgorithm->name());
        } else {
            KeyChecker::checkKeyAlgorithm($recipientKey, $contentEncryptionAlgorithm->name());
        }
    }

    /**
     * @param list<KeyEncryptionAlgorithm> $keyEncryptionAlgorithms
     * @param array<string, mixed> $additionalHeader
     */
    private function determineCEK(
        string $keyManagementMode,
        array $keyEncryptionAlgorithms,
        ContentEncryptionAlgorithm $contentEncryptionAlgorithm,
        array &$additionalHeader
    ): string {
        switch ($keyManagementMode) {
            case KeyEncryption::MODE_ENCRYPT:
            case KeyEncryption::MODE_WRAP:
                return $this->createCEK($contentEncryptionAlgorithm->getCEKSize());

            case KeyEncryption::MODE_AGREEMENT:
                if (count($this->recipients) !== 1) {
                    throw new LogicException(
                        'Unable to encrypt for multiple recipients using key agreement algorithms.'
                    );
                }
                $algorithm = $keyEncryptionAlgorithms[0];
                if (! $algorithm instanceof KeyAgreement) {
                    throw new UnsupportedAlgorithmException('Invalid content encryption algorithm');
                }

                return $algorithm->getAgreementKey(
                    $contentEncryptionAlgorithm->getCEKSize(),
                    $contentEncryptionAlgorithm->name(),
                    $this->recipients[0]->key,
                    $this->senderKey,
                    $this->getCompleteHeader($this->recipients[0]),
                    $additionalHeader
                );

            case KeyEncryption::MODE_DIRECT:
                if (count($this->recipients) !== 1) {
                    throw new LogicException(
                        'Unable to encrypt for multiple recipients using key agreement algorithms.'
                    );
                }
                $key = $this->recipients[0]->key;
                if ($key->get('kty') !== 'oct') {
                    throw new RuntimeException('Wrong key type.');
                }
                $k = $key->get('k');
                if (! is_string($k)) {
                    throw new RuntimeException('Invalid key.');
                }

                return Base64UrlSafe::decodeNoPadding($k);

            default:
                throw new InvalidArgumentException(sprintf(
                    'Unsupported key management mode "%s".',
                    $keyManagementMode
                ));
        }
    }

    private function areKeyManagementModesCompatible(string $current, string $new): bool
    {
        $agree = KeyEncryptionAlgorithm::MODE_AGREEMENT;
        $dir = KeyEncryptionAlgorithm::MODE_DIRECT;
        $enc = KeyEncryptionAlgorithm::MODE_ENCRYPT;
        $wrap = KeyEncryptionAlgorithm::MODE_WRAP;
        $supportedKeyManagementModeCombinations = [
            $enc . $enc => true,
            $enc . $wrap => true,
            $wrap . $enc => true,
            $wrap . $wrap => true,
            $agree . $agree => false,
            $agree . $dir => false,
            $agree . $enc => false,
            $agree . $wrap => false,
            $dir . $agree => false,
            $dir . $dir => false,
            $dir . $enc => false,
            $dir . $wrap => false,
            $enc . $agree => false,
            $enc . $dir => false,
            $wrap . $agree => false,
            $wrap . $dir => false,
        ];

        if (array_key_exists($current . $new, $supportedKeyManagementModeCombinations)) {
            return $supportedKeyManagementModeCombinations[$current . $new];
        }

        return false;
    }

    private function createCEK(int $size): string
    {
        return random_bytes(intdiv($size, 8));
    }

    private function createIV(int $size): string
    {
        return random_bytes(intdiv($size, 8));
    }

    /**
     * @param array<string, mixed> $completeHeader
     */
    private function getKeyEncryptionAlgorithm(array $completeHeader): KeyEncryptionAlgorithm
    {
        $alg = $completeHeader['alg'] ?? null;
        if (! is_string($alg)) {
            throw new InvalidHeaderParameterException('Parameter "alg" is missing.');
        }
        $keyEncryptionAlgorithm = $this->keyEncryptionAlgorithmManager->get($alg);
        if (! $keyEncryptionAlgorithm instanceof KeyEncryptionAlgorithm) {
            throw new InvalidArgumentException(sprintf(
                'The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.',
                $alg
            ));
        }

        return $keyEncryptionAlgorithm;
    }

    /**
     * @param array<string, mixed> $completeHeader
     */
    private function getContentEncryptionAlgorithm(array $completeHeader): ContentEncryptionAlgorithm
    {
        $enc = $completeHeader['enc'] ?? null;
        if (! is_string($enc)) {
            throw new InvalidHeaderParameterException('Parameter "enc" is missing.');
        }
        $contentEncryptionAlgorithm = $this->contentEncryptionAlgorithmManager->get($enc);
        if (! $contentEncryptionAlgorithm instanceof ContentEncryptionAlgorithm) {
            throw new UnsupportedAlgorithmException(sprintf(
                'The content encryption algorithm "%s" is not supported or not a content encryption algorithm instance.',
                $enc
            ));
        }

        return $contentEncryptionAlgorithm;
    }
}

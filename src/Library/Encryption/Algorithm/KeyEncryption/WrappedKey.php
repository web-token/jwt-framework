<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

/**
 * The key produced by a key management algorithm, together with the header parameters the algorithm needs to add
 * to the token so that the recipient is able to compute the key back.
 *
 * It is the return type announced for KeyEncryption::encryptKey(), KeyWrapping::wrapKey(),
 * KeyAgreement::getAgreementKey() and KeyAgreementWithKeyWrapping::wrapAgreementKey() in 5.0.0, where it replaces
 * the "array &$additionalHeader" output parameter. It is not used by those interfaces yet: adding it now would
 * break every third-party implementation of them.
 */
final readonly class WrappedKey
{
    /**
     * @param array<string, mixed> $additionalHeader
     */
    public function __construct(
        private string $key,
        private array $additionalHeader = []
    ) {
    }

    /**
     * The encrypted or wrapped CEK, or the agreement key when the algorithm is a key agreement algorithm.
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * The header parameters to add to the token, such as "epk", "iv", "tag" or "p2s".
     *
     * @return array<string, mixed>
     */
    public function getAdditionalHeader(): array
    {
        return $this->additionalHeader;
    }
}

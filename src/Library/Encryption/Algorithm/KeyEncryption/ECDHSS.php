<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\JWK;
use Override;

final readonly class ECDHSS extends AbstractECDH
{
    #[Override]
    public function name(): string
    {
        return 'ECDH-SS';
    }

    /**
     * The agreement only uses the two static keys, so the "epk" header parameter is never read. When the recipient key
     * is the private one, the public part of the sender key is the other key.
     *
     * @param array<string, mixed> $complete_header
     * @param array<string, mixed> $additional_header_values
     */
    #[Override]
    public function getAgreementKey(
        int $encryptionKeyLength,
        string $algorithm,
        JWK $recipientKey,
        ?JWK $senderKey,
        array $complete_header = [],
        array &$additional_header_values = []
    ): string {
        if ($senderKey === null) {
            throw new LogicException('The sender key shall be set');
        }
        [$publicKey, $privateKey] = $recipientKey->has('d')
            ? [$senderKey->toPublic(), $recipientKey]
            : [$recipientKey, $senderKey];
        $agreedKey = parent::getAgreementKey(
            $encryptionKeyLength,
            $algorithm,
            $publicKey,
            $privateKey,
            $complete_header,
            $additional_header_values
        );
        unset($additional_header_values['epk']);

        return $agreedKey;
    }
}

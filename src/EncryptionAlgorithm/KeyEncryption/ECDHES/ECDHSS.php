<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\JWK;
use LogicException;

final class ECDHSS extends AbstractECDH
{
    /**
     * @param array<string, mixed> $complete_header
     * @param array<string, mixed> $additional_header_values
     */
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
        $agreedKey = parent::getAgreementKey(
            $encryptionKeyLength,
            $algorithm,
            $recipientKey,
            $senderKey,
            $complete_header,
            $additional_header_values
        );
        unset($additional_header_values['epk']);

        return $agreedKey;
    }
}

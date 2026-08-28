<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;

interface KeyAgreement extends KeyEncryptionAlgorithm
{
    /**
     * Computes the agreement key.
     *
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeaderValues
     *
     * BC NOTE: in 5.0, this method will return a "WrappedKey" object - the agreement key and the header parameters
     * to add to the token - and the "array &$additionalHeaderValues" output parameter will be removed. The change
     * cannot be made now without breaking every implementation of this interface. Implementations are encouraged to
     * prepare for it: the object is already available as
     * Jose\Component\Encryption\Algorithm\KeyEncryption\WrappedKey.
     */
    public function getAgreementKey(
        int $encryptionKeyLength,
        string $algorithm,
        JWK $recipientKey,
        ?JWK $senderKey,
        array $completeHeader = [],
        array &$additionalHeaderValues = []
    ): string;
}

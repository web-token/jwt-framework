<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A128KW;
use AESKW\A192KW;
use AESKW\A256KW;
use Jose\Component\Core\JWK;

abstract class ECDHESAESKW implements KeyAgreementWithKeyWrapping
{
    public function allowedKeyTypes(): array
    {
        return ['EC', 'OKP'];
    }

    public function wrapAgreementKey(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $cek,
        int $encryption_key_length,
        array $complete_header,
        array &$additional_header_values
    ): string {
        $ecdh_es = new ECDHES();
        $agreement_key = $ecdh_es->getAgreementKey(
            $this->getKeyLength(),
            $this->name(),
            $recipientKey->toPublic(),
            $senderKey,
            $complete_header,
            $additional_header_values
        );
        $wrapper = $this->getWrapper();

        return $wrapper::wrap($agreement_key, $cek);
    }

    public function unwrapAgreementKey(
        JWK $recipientKey,
        ?JWK $senderKey,
        string $encrypted_cek,
        int $encryption_key_length,
        array $complete_header
    ): string {
        $ecdh_es = new ECDHES();
        $agreement_key = $ecdh_es->getAgreementKey(
            $this->getKeyLength(),
            $this->name(),
            $recipientKey,
            $senderKey,
            $complete_header
        );
        $wrapper = $this->getWrapper();

        return $wrapper::unwrap($agreement_key, $encrypted_cek);
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    abstract protected function getWrapper(): A128KW|A192KW|A256KW;

    abstract protected function getKeyLength(): int;
}

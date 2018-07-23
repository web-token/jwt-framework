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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Core\JWK;

abstract class ECDHESAESKW implements KeyAgreementWithKeyWrapping
{
    /**
     * {@inheritdoc}
     */
    public function allowedKeyTypes(): array
    {
        return ['EC', 'OKP'];
    }

    /**
     * {@inheritdoc}
     */
    public function wrapAgreementKey(JWK $receiver_key, string $cek, int $encryption_key_length, array $complete_header, array &$additional_header_values): string
    {
        $ecdh_es = new ECDHES();
        $agreement_key = $ecdh_es->getAgreementKey($this->getKeyLength(), $this->name(), $receiver_key->toPublic(), $complete_header, $additional_header_values);
        $wrapper = $this->getWrapper();

        return $wrapper::wrap($agreement_key, $cek);
    }

    /**
     * {@inheritdoc}
     */
    public function unwrapAgreementKey(JWK $receiver_key, string $encrypted_cek, int $encryption_key_length, array $complete_header): string
    {
        $ecdh_es = new ECDHES();
        $agreement_key = $ecdh_es->getAgreementKey($this->getKeyLength(), $this->name(), $receiver_key, $complete_header);
        $wrapper = $this->getWrapper();

        return $wrapper::unwrap($agreement_key, $encrypted_cek);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    /**
     * @return \AESKW\A128KW|\AESKW\A192KW|\AESKW\A256KW
     */
    abstract protected function getWrapper();

    abstract protected function getKeyLength(): int;
}

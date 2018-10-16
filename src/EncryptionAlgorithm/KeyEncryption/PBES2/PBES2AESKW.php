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

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

abstract class PBES2AESKW implements KeyWrapping
{
    /**
     * @var int
     */
    private $salt_size;

    /**
     * @var int
     */
    private $nb_count;

    public function __construct(int $salt_size = 64, int $nb_count = 4096)
    {
        $this->salt_size = $salt_size;
        $this->nb_count = $nb_count;
    }

    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function wrapKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $this->checkKey($key);
        $this->checkHeaderAlgorithm($completeHeader);
        $wrapper = $this->getWrapper();
        $hash_algorithm = $this->getHashAlgorithm();
        $key_size = $this->getKeySize();
        $salt = \random_bytes($this->salt_size);
        $password = Base64Url::decode($key->get('k'));

        // We set header parameters
        $additionalHeader['p2s'] = Base64Url::encode($salt);
        $additionalHeader['p2c'] = $this->nb_count;

        $derived_key = \hash_pbkdf2($hash_algorithm, $password, $completeHeader['alg']."\x00".$salt, $this->nb_count, $key_size, true);

        return $wrapper::wrap($derived_key, $cek);
    }

    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $this->checkKey($key);
        $this->checkHeaderAlgorithm($completeHeader);
        $this->checkHeaderAdditionalParameters($completeHeader);
        $wrapper = $this->getWrapper();
        $hash_algorithm = $this->getHashAlgorithm();
        $key_size = $this->getKeySize();
        $salt = $completeHeader['alg']."\x00".Base64Url::decode($completeHeader['p2s']);
        $count = $completeHeader['p2c'];
        $password = Base64Url::decode($key->get('k'));

        $derived_key = \hash_pbkdf2($hash_algorithm, $password, $salt, $count, $key_size, true);

        return $wrapper::unwrap($derived_key, $encrypted_cek);
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    protected function checkKey(JWK $key)
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        if (!$key->has('k')) {
            throw new \InvalidArgumentException('The key parameter "k" is missing.');
        }
    }

    protected function checkHeaderAlgorithm(array $header)
    {
        if (!\array_key_exists('alg', $header)) {
            throw new \InvalidArgumentException('The header parameter "alg" is missing.');
        }
        if (!\is_string($header['alg'])) {
            throw new \InvalidArgumentException('The header parameter "alg" is not valid.');
        }
    }

    protected function checkHeaderAdditionalParameters(array $header)
    {
        foreach (['p2s', 'p2c'] as $k) {
            if (!\array_key_exists($k, $header)) {
                throw new \InvalidArgumentException(\sprintf('The header parameter "%s" is missing.', $k));
            }
            if (empty($header[$k])) {
                throw new \InvalidArgumentException(\sprintf('The header parameter "%s" is not valid.', $k));
            }
        }
    }

    /**
     * @return \AESKW\A128KW|\AESKW\A192KW|\AESKW\A256KW
     */
    abstract protected function getWrapper();

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getKeySize(): int;
}

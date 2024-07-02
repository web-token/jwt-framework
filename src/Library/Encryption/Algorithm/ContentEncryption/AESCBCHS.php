<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use RuntimeException;
use function extension_loaded;
use const OPENSSL_RAW_DATA;

abstract class AESCBCHS implements ContentEncryptionAlgorithm
{
    public function __construct()
    {
        if (! extension_loaded('openssl')) {
            throw new RuntimeException('Please install the OpenSSL extension');
        }
    }

    public function allowedKeyTypes(): array
    {
        return []; //Irrelevant
    }

    public function encryptContent(
        string $data,
        string $cek,
        string $iv,
        ?string $aad,
        string $encoded_protected_header,
        ?string &$tag = null
    ): string {
        $k = mb_substr($cek, $this->getCEKSize() / 16, null, '8bit');
        $result = openssl_encrypt($data, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if ($result === false) {
            throw new RuntimeException('Unable to encrypt the content');
        }

        $tag = $this->calculateAuthenticationTag($result, $cek, $iv, $aad, $encoded_protected_header);

        return $result;
    }

    public function decryptContent(
        string $data,
        string $cek,
        string $iv,
        ?string $aad,
        string $encoded_protected_header,
        string $tag
    ): string {
        if (! $this->isTagValid($data, $cek, $iv, $aad, $encoded_protected_header, $tag)) {
            throw new RuntimeException('Unable to decrypt or to verify the tag.');
        }
        $k = mb_substr($cek, $this->getCEKSize() / 16, null, '8bit');

        $result = openssl_decrypt($data, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if ($result === false) {
            throw new RuntimeException('Unable to decrypt or to verify the tag.');
        }

        return $result;
    }

    public function getIVSize(): int
    {
        return 128;
    }

    protected function calculateAuthenticationTag(
        string $encrypted_data,
        string $cek,
        string $iv,
        ?string $aad,
        string $encoded_header
    ): string {
        $calculated_aad = $encoded_header;
        if ($aad !== null) {
            $calculated_aad .= '.' . Base64UrlSafe::encodeUnpadded($aad);
        }
        $mac_key = mb_substr($cek, 0, $this->getCEKSize() / 16, '8bit');
        $auth_data_length = mb_strlen($encoded_header, '8bit');

        $secured_input = implode('', [
            $calculated_aad,
            $iv,
            $encrypted_data,
            pack('N2', ($auth_data_length / 2_147_483_647) * 8, ($auth_data_length % 2_147_483_647) * 8),
        ]);
        $hash = hash_hmac($this->getHashAlgorithm(), $secured_input, $mac_key, true);

        return mb_substr($hash, 0, mb_strlen($hash, '8bit') / 2, '8bit');
    }

    protected function isTagValid(
        string $encrypted_data,
        string $cek,
        string $iv,
        ?string $aad,
        string $encoded_header,
        string $authentication_tag
    ): bool {
        return hash_equals(
            $authentication_tag,
            $this->calculateAuthenticationTag($encrypted_data, $cek, $iv, $aad, $encoded_header)
        );
    }

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getMode(): string;
}

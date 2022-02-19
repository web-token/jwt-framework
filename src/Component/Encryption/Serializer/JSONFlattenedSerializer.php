<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Serializer;

use function array_key_exists;
use function count;
use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Recipient;
use ParagonIE\ConstantTime\Base64UrlSafe;

final class JSONFlattenedSerializer implements JWESerializer
{
    public const NAME = 'jwe_json_flattened';

    public function displayName(): string
    {
        return 'JWE JSON Flattened';
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function serialize(JWE $jwe, ?int $recipientIndex = null): string
    {
        if ($recipientIndex === null) {
            $recipientIndex = 0;
        }
        $recipient = $jwe->getRecipient($recipientIndex);
        $data = [
            'ciphertext' => Base64UrlSafe::encodeUnpadded($jwe->getCiphertext() ?? ''),
            'iv' => Base64UrlSafe::encodeUnpadded($jwe->getIV() ?? ''),
            'tag' => Base64UrlSafe::encodeUnpadded($jwe->getTag() ?? ''),
        ];
        if ($jwe->getAAD() !== null) {
            $data['aad'] = Base64UrlSafe::encodeUnpadded($jwe->getAAD());
        }
        if (count($jwe->getSharedProtectedHeader()) !== 0) {
            $data['protected'] = $jwe->getEncodedSharedProtectedHeader();
        }
        if (count($jwe->getSharedHeader()) !== 0) {
            $data['unprotected'] = $jwe->getSharedHeader();
        }
        if (count($recipient->getHeader()) !== 0) {
            $data['header'] = $recipient->getHeader();
        }
        if ($recipient->getEncryptedKey() !== null) {
            $data['encrypted_key'] = Base64UrlSafe::encodeUnpadded($recipient->getEncryptedKey());
        }

        return JsonConverter::encode($data);
    }

    public function unserialize(string $input): JWE
    {
        $data = JsonConverter::decode($input);
        if (! is_array($data)) {
            throw new InvalidArgumentException('Unsupported input.');
        }
        $this->checkData($data);

        $ciphertext = Base64UrlSafe::decode($data['ciphertext']);
        $iv = Base64UrlSafe::decode($data['iv']);
        $tag = Base64UrlSafe::decode($data['tag']);
        $aad = array_key_exists('aad', $data) ? Base64UrlSafe::decode($data['aad']) : null;
        [$encodedSharedProtectedHeader, $sharedProtectedHeader, $sharedHeader] = $this->processHeaders($data);
        $encryptedKey = array_key_exists('encrypted_key', $data) ? Base64UrlSafe::decode($data['encrypted_key']) : null;
        $header = array_key_exists('header', $data) ? $data['header'] : [];

        return new JWE(
            $ciphertext,
            $iv,
            $tag,
            $aad,
            $sharedHeader,
            $sharedProtectedHeader,
            $encodedSharedProtectedHeader,
            [new Recipient($header, $encryptedKey)]
        );
    }

    private function checkData(?array $data): void
    {
        if ($data === null || ! isset($data['ciphertext']) || isset($data['recipients'])) {
            throw new InvalidArgumentException('Unsupported input.');
        }
    }

    private function processHeaders(array $data): array
    {
        $encodedSharedProtectedHeader = array_key_exists('protected', $data) ? $data['protected'] : null;
        $sharedProtectedHeader = $encodedSharedProtectedHeader ? JsonConverter::decode(
            Base64UrlSafe::decode($encodedSharedProtectedHeader)
        ) : [];
        $sharedHeader = $data['unprotected'] ?? [];

        return [$encodedSharedProtectedHeader, $sharedProtectedHeader, $sharedHeader];
    }
}

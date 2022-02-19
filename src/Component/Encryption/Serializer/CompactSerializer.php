<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Serializer;

use function count;
use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Recipient;
use LogicException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Throwable;

final class CompactSerializer implements JWESerializer
{
    public const NAME = 'jwe_compact';

    public function displayName(): string
    {
        return 'JWE Compact';
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

        $this->checkHasNoAAD($jwe);
        $this->checkHasSharedProtectedHeader($jwe);
        $this->checkRecipientHasNoHeader($jwe, $recipientIndex);

        return sprintf(
            '%s.%s.%s.%s.%s',
            $jwe->getEncodedSharedProtectedHeader(),
            Base64UrlSafe::encodeUnpadded($recipient->getEncryptedKey() ?? ''),
            Base64UrlSafe::encodeUnpadded($jwe->getIV() ?? ''),
            Base64UrlSafe::encodeUnpadded($jwe->getCiphertext() ?? ''),
            Base64UrlSafe::encodeUnpadded($jwe->getTag() ?? '')
        );
    }

    public function unserialize(string $input): JWE
    {
        $parts = explode('.', $input);
        if (count($parts) !== 5) {
            throw new InvalidArgumentException('Unsupported input');
        }

        try {
            $encodedSharedProtectedHeader = $parts[0];
            $sharedProtectedHeader = JsonConverter::decode(Base64UrlSafe::decode($encodedSharedProtectedHeader));
            if (! is_array($sharedProtectedHeader)) {
                throw new InvalidArgumentException('Unsupported input.');
            }
            $encryptedKey = $parts[1] === '' ? null : Base64UrlSafe::decode($parts[1]);
            $iv = Base64UrlSafe::decode($parts[2]);
            $ciphertext = Base64UrlSafe::decode($parts[3]);
            $tag = Base64UrlSafe::decode($parts[4]);

            return new JWE(
                $ciphertext,
                $iv,
                $tag,
                null,
                [],
                $sharedProtectedHeader,
                $encodedSharedProtectedHeader,
                [new Recipient([], $encryptedKey)]
            );
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unsupported input', $throwable->getCode(), $throwable);
        }
    }

    private function checkHasNoAAD(JWE $jwe): void
    {
        if ($jwe->getAAD() !== null) {
            throw new LogicException('This JWE has AAD and cannot be converted into Compact JSON.');
        }
    }

    private function checkRecipientHasNoHeader(JWE $jwe, int $id): void
    {
        if (count($jwe->getSharedHeader()) !== 0 || count($jwe->getRecipient($id)->getHeader()) !== 0) {
            throw new LogicException(
                'This JWE has shared header parameters or recipient header parameters and cannot be converted into Compact JSON.'
            );
        }
    }

    private function checkHasSharedProtectedHeader(JWE $jwe): void
    {
        if (count($jwe->getSharedProtectedHeader()) === 0) {
            throw new LogicException(
                'This JWE does not have shared protected header parameters and cannot be converted into Compact JSON.'
            );
        }
    }
}

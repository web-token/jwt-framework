<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Exception;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSS;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The EC keys are the ones of RFC 7518 appendix C: Bob is the recipient, and the ephemeral key of Alice is used as the
 * static key of the sender for ECDH-SS.
 *
 * @internal
 */
final class DirectModeEncryptedKeyTest extends EncryptionTestCase
{
    private const PAYLOAD = '{"sub":"alice","adm":0}';

    private const FILLING = 'chosen by the token holder';

    private const SHARED_KEY = [
        'kty' => 'oct',
        'k' => 'ZgkktPE6jYsYXALmI9YQf-bTr7PN-yCDJEErHYHTmTE',
    ];

    private const RECIPIENT_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
        'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
    ];

    private const SENDER_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
    ];

    #[DataProvider('dataDirectModes')]
    #[Test]
    public function aTokenWithAFilledEncryptedKeyIsRejected(string $alg, string $format): void
    {
        $token = $this->issue($alg, $format);

        static::assertSame(self::PAYLOAD, $this->decrypt($alg, $token));
        static::assertNull($this->decrypt($alg, self::withEncryptedKey($token, $format, self::FILLING)));
        static::assertNull($this->decrypt($alg, self::withEncryptedKey($token, $format, "\0")));
    }

    #[DataProvider('dataDirectModesInJson')]
    #[Test]
    public function anEncryptedKeyMemberThatDecodesToNothingIsAccepted(string $alg, string $format): void
    {
        $token = self::withEncryptedKey($this->issue($alg, $format), $format, '');

        static::assertSame(self::PAYLOAD, $this->decrypt($alg, $token));
    }

    #[Test]
    public function theLoaderRejectsATokenWithAFilledEncryptedKey(): void
    {
        $token = self::withEncryptedKey($this->issue('dir', 'jwe_compact'), 'jwe_compact', self::FILLING);
        $loader = $this->getJWELoaderFactory()
            ->create(['jwe_compact'], ['dir', 'A256GCM']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unable to load and decrypt the token.');

        $loader->loadAndDecryptWithKey($token, new JWK(self::SHARED_KEY), $recipient);
    }

    public static function dataDirectModes(): iterable
    {
        foreach (['dir', 'ECDH-ES', 'ECDH-SS'] as $alg) {
            foreach (['jwe_compact', 'jwe_json_flattened', 'jwe_json_general'] as $format) {
                yield $alg . ', ' . $format => [$alg, $format];
            }
        }
    }

    public static function dataDirectModesInJson(): iterable
    {
        foreach (self::dataDirectModes() as $name => [$alg, $format]) {
            if ($format !== 'jwe_compact') {
                yield $name => [$alg, $format];
            }
        }
    }

    private function issue(string $alg, string $format): string
    {
        $jwe = match ($alg) {
            'ECDH-SS' => self::issueWithStaticKeys(),
            default => $this->getJWEBuilderFactory()
                ->create([$alg, 'A256GCM'])
                ->create()
                ->withPayload(self::PAYLOAD)
                ->withSharedProtectedHeader([
                    'alg' => $alg,
                    'enc' => 'A256GCM',
                ])
                ->addRecipient($alg === 'dir' ? new JWK(self::SHARED_KEY) : (new JWK(self::RECIPIENT_KEY))->toPublic())
                ->build(),
        };

        return $this->getJWESerializerManager()
            ->serialize($format, $jwe, 0);
    }

    /**
     * The builder of this branch cannot issue an ECDH-SS token, so the key is agreed and the content encrypted here.
     */
    private static function issueWithStaticKeys(): JWE
    {
        $header = [
            'alg' => 'ECDH-SS',
            'enc' => 'A256GCM',
        ];
        $encodedHeader = Base64UrlSafe::encodeUnpadded(JsonConverter::encode($header));
        $additionalHeaderValues = [];
        $cek = (new ECDHSS())->getAgreementKey(
            256,
            'A256GCM',
            (new JWK(self::RECIPIENT_KEY))->toPublic(),
            new JWK(self::SENDER_KEY),
            $header,
            $additionalHeaderValues
        );
        $iv = random_bytes(12);
        $tag = null;
        $ciphertext = (new A256GCM())->encryptContent(self::PAYLOAD, $cek, $iv, null, $encodedHeader, $tag);

        return (new CompactSerializer())->unserialize(implode('.', [
            $encodedHeader,
            '',
            Base64UrlSafe::encodeUnpadded($iv),
            Base64UrlSafe::encodeUnpadded($ciphertext),
            Base64UrlSafe::encodeUnpadded($tag ?? ''),
        ]));
    }

    private static function withEncryptedKey(string $token, string $format, string $encryptedKey): string
    {
        $encoded = Base64UrlSafe::encodeUnpadded($encryptedKey);
        if ($format === 'jwe_compact') {
            $parts = explode('.', $token);
            $parts[1] = $encoded;

            return implode('.', $parts);
        }
        $data = JsonConverter::decode($token);
        if ($format === 'jwe_json_general') {
            $data['recipients'][0]['encrypted_key'] = $encoded;
        } else {
            $data['encrypted_key'] = $encoded;
        }

        return JsonConverter::encode($data);
    }

    /**
     * With ECDH-SS, the decrypter takes the public key of the sender as the key and the private key of the recipient
     * as the sender key.
     */
    private function decrypt(string $alg, string $token): ?string
    {
        $jwe = $this->getJWESerializerManager()
            ->unserialize($token);
        [$key, $senderKey] = match ($alg) {
            'dir' => [new JWK(self::SHARED_KEY), null],
            'ECDH-ES' => [new JWK(self::RECIPIENT_KEY), null],
            default => [(new JWK(self::SENDER_KEY))->toPublic(), new JWK(self::RECIPIENT_KEY)],
        };
        $decrypted = $this->getJWEDecrypterFactory()
            ->create([$alg, 'A256GCM'])
            ->decryptUsingKeySet($jwe, new JWKSet([$key]), 0, $usedKey, $senderKey);

        return $decrypted ? $jwe->getPayload() : null;
    }
}

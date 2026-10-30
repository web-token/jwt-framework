<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\KeyEncryption\HPKE;

use Jose\Component\Core\Exception\DecryptionFailedException;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE\CipherSuite;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function chr;
use function ord;
use function sprintf;
use const JSON_THROW_ON_ERROR;

/**
 * The HPKE primitives behind the JOSE algorithms, checked against the test vectors of RFC 9180, which
 * draft-ietf-hpke-hpke-03 keeps unchanged (https://github.com/cfrg/draft-irtf-cfrg-hpke, commit 5f503c5).
 *
 * The fixture keeps the base and PSK modes of the seven JOSE cipher suites the file covers, with the first
 * encryption of each, the single-shot API using sequence number 0 only. DHKEM(P-384, HKDF-SHA384) is not in the file:
 * HPKE-1 is covered by the vectors of draft-ietf-jose-hpke-encrypt instead.
 *
 * @internal
 */
final class CipherSuiteTest extends TestCase
{
    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function vectors(): iterable
    {
        $vectors = json_decode(
            (string) file_get_contents(__DIR__ . '/../../../fixtures/rfc9180/test-vectors.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        foreach ($vectors as $vector) {
            $name = sprintf(
                'mode %d, KEM 0x%04x, KDF 0x%04x, AEAD 0x%04x',
                $vector['mode'],
                $vector['kem_id'],
                $vector['kdf_id'],
                $vector['aead_id']
            );

            yield $name => [$vector];
        }
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function theKeyPairsAreDerivedFromTheInputKeyingMaterial(array $vector): void
    {
        $suite = $this->suite($vector);

        static::assertSame(
            [$vector['skEm'], $vector['pkEm']],
            array_map(bin2hex(...), $suite->kem->deriveKeyPair(hex2bin($vector['ikmE'])))
        );
        static::assertSame(
            [$vector['skRm'], $vector['pkRm']],
            array_map(bin2hex(...), $suite->kem->deriveKeyPair(hex2bin($vector['ikmR'])))
        );
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function theSenderAndTheRecipientShareTheSecretOfTheVector(array $vector): void
    {
        $suite = $this->suite($vector);

        [$sharedSecret, $encapsulatedKey] = $suite->kem->encapsulate(
            hex2bin($vector['pkRm']),
            hex2bin($vector['ikmE'])
        );

        static::assertSame($vector['enc'], bin2hex($encapsulatedKey));
        static::assertSame($vector['shared_secret'], bin2hex($sharedSecret));
        static::assertSame(
            $vector['shared_secret'],
            bin2hex($suite->kem->decapsulate(
                hex2bin($vector['enc']),
                hex2bin($vector['skRm']),
                hex2bin($vector['pkRm'])
            ))
        );
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function theKeyScheduleGivesTheKeyAndTheNonceOfTheVector(array $vector): void
    {
        $suite = $this->suite($vector);

        [$key, $baseNonce] = $suite->keySchedule(
            hex2bin($vector['shared_secret']),
            hex2bin($vector['info']),
            hex2bin($vector['psk'] ?? ''),
            hex2bin($vector['psk_id'] ?? '')
        );

        static::assertSame($vector['key'], bin2hex($key));
        static::assertSame($vector['base_nonce'], bin2hex($baseNonce));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function theSingleShotEncryptionGivesTheCiphertextOfTheVector(array $vector): void
    {
        $suite = $this->suite($vector);

        [$encapsulatedKey, $ciphertext] = $suite->seal(
            hex2bin($vector['pkRm']),
            hex2bin($vector['info']),
            hex2bin($vector['encryption']['aad']),
            hex2bin($vector['encryption']['pt']),
            hex2bin($vector['psk'] ?? ''),
            hex2bin($vector['psk_id'] ?? ''),
            hex2bin($vector['ikmE'])
        );

        static::assertSame($vector['enc'], bin2hex($encapsulatedKey));
        static::assertSame($vector['encryption']['ct'], bin2hex($ciphertext));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function theSingleShotDecryptionGivesThePlaintextOfTheVector(array $vector): void
    {
        $suite = $this->suite($vector);

        static::assertSame($vector['encryption']['pt'], bin2hex($suite->open(
            hex2bin($vector['enc']),
            hex2bin($vector['skRm']),
            hex2bin($vector['pkRm']),
            hex2bin($vector['info']),
            hex2bin($vector['encryption']['aad']),
            hex2bin($vector['encryption']['ct']),
            hex2bin($vector['psk'] ?? ''),
            hex2bin($vector['psk_id'] ?? '')
        )));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function aFreshEncryptionIsDecrypted(array $vector): void
    {
        $suite = $this->suite($vector);
        $plaintext = 'Beauty is truth, truth beauty';

        [$encapsulatedKey, $ciphertext] = $suite->seal(
            hex2bin($vector['pkRm']),
            'info',
            'aad',
            $plaintext,
            hex2bin($vector['psk'] ?? ''),
            hex2bin($vector['psk_id'] ?? '')
        );

        static::assertNotSame($vector['enc'], bin2hex($encapsulatedKey));
        static::assertSame($plaintext, $suite->open(
            $encapsulatedKey,
            hex2bin($vector['skRm']),
            hex2bin($vector['pkRm']),
            'info',
            'aad',
            $ciphertext,
            hex2bin($vector['psk'] ?? ''),
            hex2bin($vector['psk_id'] ?? '')
        ));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function alterations(): iterable
    {
        yield 'another info' => ['info', 'other info', 'aad'];
        yield 'another associated data' => ['aad', 'info', 'other aad'];
        yield 'a modified ciphertext' => ['ciphertext', 'info', 'aad'];
        yield 'a modified encapsulated key' => ['enc', 'info', 'aad'];
    }

    #[Test]
    #[DataProvider('alterations')]
    public function anAlteredInputIsNotDecrypted(string $altered, string $info, string $aad): void
    {
        $suite = CipherSuite::fromIdentifiers(0x0020, 0x0001, 0x0001);
        if (! $suite->isSupported()) {
            static::markTestSkipped('X25519 is not available on this platform.');
        }
        [$privateKey, $publicKey] = $suite->kem->deriveKeyPair(random_bytes(32));
        [$encapsulatedKey, $ciphertext] = $suite->seal($publicKey, 'info', 'aad', 'Beauty is truth, truth beauty');
        if ($altered === 'ciphertext') {
            $ciphertext = substr_replace($ciphertext, chr(ord($ciphertext[0]) ^ 1), 0, 1);
        }
        if ($altered === 'enc') {
            [, $encapsulatedKey] = $suite->kem->deriveKeyPair(random_bytes(32));
        }

        $this->expectException(DecryptionFailedException::class);

        $suite->open($encapsulatedKey, $privateKey, $publicKey, $info, $aad, $ciphertext);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function inconsistentPreSharedKeyInputs(): iterable
    {
        yield 'a key without identifier' => [str_repeat('k', 32), ''];
        yield 'an identifier without key' => ['', 'psk-1'];
        yield 'a key shorter than 32 bytes' => [str_repeat('k', 31), 'psk-1'];
    }

    #[Test]
    #[DataProvider('inconsistentPreSharedKeyInputs')]
    public function thePreSharedKeyInputsAreChecked(string $psk, string $pskId): void
    {
        $suite = CipherSuite::fromIdentifiers(0x0010, 0x0001, 0x0001);

        $this->expectException(InvalidArgumentException::class);

        $suite->keySchedule(str_repeat("\x01", 32), '', $psk, $pskId);
    }

    #[Test]
    public function anUnknownIdentifierIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        CipherSuite::fromIdentifiers(0x0010, 0x0001, 0xFFFF);
    }

    /**
     * @param array<string, mixed> $vector
     */
    private function suite(array $vector): CipherSuite
    {
        $suite = CipherSuite::fromIdentifiers($vector['kem_id'], $vector['kdf_id'], $vector['aead_id']);
        if (! $suite->isSupported()) {
            static::markTestSkipped('The cipher suite is not available on this platform.');
        }

        return $suite;
    }
}

<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreement;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const OPENSSL_RAW_DATA;

/**
 * The keys are the ones of RFC 7518 appendix C: the recipient key of Bob and the ephemeral key of Alice.
 *
 * @internal
 */
final class ECDHESKeyDerivationTest extends TestCase
{
    private const RECIPIENT_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
        'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
    ];

    private const EPHEMERAL_PUBLIC_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
    ];

    private const PAYLOAD = 'Live long and prosper.';

    /**
     * The expected keys were computed with the Concat KDF of the Python "cryptography" package, using the shared
     * secret and the PartyUInfo/PartyVInfo values of RFC 7518 appendix C. The A128GCM key is the one the appendix
     * gives. A192CBC-HS384 and A256CBC-HS512 need more than one SHA-256 round.
     */
    #[Test]
    #[DataProvider('derivedKeys')]
    public function theKeyIsDerivedOnTheLengthTheContentEncryptionAlgorithmNeeds(
        string $enc,
        int $size,
        string $expectedKey
    ): void {
        $additionalHeaderValues = [];
        $key = (new ECDHES())->getAgreementKey($size, $enc, new JWK(self::RECIPIENT_KEY), null, [
            'alg' => 'ECDH-ES',
            'enc' => $enc,
            'apu' => 'QWxpY2U',
            'apv' => 'Qm9i',
            'epk' => self::EPHEMERAL_PUBLIC_KEY,
        ], $additionalHeaderValues);

        static::assertSame($expectedKey, Base64UrlSafe::encodeUnpadded($key));
    }

    /**
     * @return iterable<string, array{string, int, string}>
     */
    public static function derivedKeys(): iterable
    {
        yield 'A128GCM' => ['A128GCM', 128, 'VqqN6vgjbSBcIijNcacQGg'];
        yield 'A192CBC-HS384' => [
            'A192CBC-HS384',
            384,
            'YFl7v565kcUWLxnzcownRAp0YC-ias5IeWtqkyLdE8vCbVC-M0KZLcy0XIGntdW3',
        ];
        yield 'A256CBC-HS512' => [
            'A256CBC-HS512',
            512,
            'OYaqefY5ZCDlgOXTiQ9iP-5dRSIweSnrme40JaAB7MF1sXVOP7ZEzoJQNLViUj6aiAa8qNdq-oYem3lRWAMiXQ',
        ];
    }

    /**
     * The tokens were produced by panva/jose 5.9.6 for the recipient key, with the ephemeral key and the
     * PartyUInfo/PartyVInfo values of RFC 7518 appendix C.
     */
    #[Test]
    #[DataProvider('tokensFromAnotherImplementation')]
    public function aTokenProducedByAnotherImplementationIsDecrypted(string $enc, string $token): void
    {
        $jwe = (new CompactSerializer())->unserialize($token);
        $decrypter = new JWEDecrypter(new AlgorithmManager([
            new ECDHES(),
            new A192CBCHS384(),
            new A256CBCHS512(),
        ]), null);

        static::assertSame($enc, $jwe->getSharedProtectedHeaderParameter('enc'));
        static::assertTrue($decrypter->decryptUsingKey($jwe, new JWK(self::RECIPIENT_KEY), 0));
        static::assertSame(self::PAYLOAD, $jwe->getPayload());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function tokensFromAnotherImplementation(): iterable
    {
        yield 'A192CBC-HS384' => [
            'A192CBC-HS384',
            'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTE5MkNCQy1IUzM4NCIsImVwayI6eyJ4IjoiZ0kwR0FJTEJkdTdUNTNha3JGbU15R2NzRjNuNWRPN01td05CSEtXNVNWMCIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ5IjoiU0xXX3hTZmZ6bFBXckhFVkkzMERITV80ZWdWd3QzTlFxZVVEN25NRnBwcyJ9LCJhcHUiOiJRV3hwWTJVIiwiYXB2IjoiUW05aSJ9..dXfM8wRKvZfFNjtt0Cqrrg.EKEkXDfFEfVl7Im4JZwNgeM6KoSpUuW2v4WrEx8KT6U.cq_xXWQEQBAVM_ELlOnQGl0JR-ahAlyy',
        ];
        yield 'A256CBC-HS512' => [
            'A256CBC-HS512',
            'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJ4IjoiZ0kwR0FJTEJkdTdUNTNha3JGbU15R2NzRjNuNWRPN01td05CSEtXNVNWMCIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ5IjoiU0xXX3hTZmZ6bFBXckhFVkkzMERITV80ZWdWd3QzTlFxZVVEN25NRnBwcyJ9LCJhcHUiOiJRV3hwWTJVIiwiYXB2IjoiUW05aSJ9..us6uN5Nj81ZlICtsPzUAKA.8EZgzuQ5Mw2v3iCCUN2Zc7tsdbL55jGLPS8VdQyVLFk.VycEfyPUPIToDU2NspgGOhWL6rZr9LOdMq7O9xvDB5M',
        ];
    }

    #[Test]
    public function theContentCannotBeDecryptedWithAnAllZeroKey(): void
    {
        $algorithmManager = new AlgorithmManager([new ECDHES(), new A256CBCHS512()]);
        $jwe = (new JWEBuilder($algorithmManager))
            ->create()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-ES',
                'enc' => 'A256CBC-HS512',
            ])
            ->addRecipient((new JWK(self::RECIPIENT_KEY))->toPublic())
            ->build();

        $withZeroKey = openssl_decrypt(
            $jwe->getCiphertext() ?? '',
            'aes-256-cbc',
            str_repeat("\0", 32),
            OPENSSL_RAW_DATA,
            $jwe->getIV() ?? ''
        );
        static::assertNotSame(self::PAYLOAD, $withZeroKey);

        $loaded = (new CompactSerializer())->unserialize((new CompactSerializer())->serialize($jwe, 0));
        static::assertTrue(
            (new JWEDecrypter($algorithmManager, null))->decryptUsingKey($loaded, new JWK(self::RECIPIENT_KEY), 0)
        );
        static::assertSame(self::PAYLOAD, $loaded->getPayload());
    }

    #[Test]
    public function theBuilderRejectsAnAgreementKeyOfTheWrongLength(): void
    {
        $builder = new JWEBuilder(new AlgorithmManager([
            self::keyAgreementReturning(random_bytes(32)),
            new A256CBCHS512(),
        ]));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid CEK size');

        $builder
            ->create()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-ES',
                'enc' => 'A256CBC-HS512',
            ])
            ->addRecipient((new JWK(self::RECIPIENT_KEY))->toPublic())
            ->build();
    }

    /**
     * The token is encrypted the way the library did before the key derivation was fixed: a 32-byte key for
     * A256CBC-HS512. It decrypts when the key agreement returns that same key, unless its length is checked.
     */
    #[Test]
    public function theDecrypterRejectsAnAgreementKeyOfTheWrongLength(): void
    {
        $cek = random_bytes(32);
        $iv = random_bytes(16);
        $tag = null;
        $encodedHeader = Base64UrlSafe::encodeUnpadded('{"alg":"ECDH-ES","enc":"A256CBC-HS512"}');
        $ciphertext = (new A256CBCHS512())->encryptContent(self::PAYLOAD, $cek, $iv, null, $encodedHeader, $tag);
        $jwe = (new CompactSerializer())->unserialize(implode('.', [
            $encodedHeader,
            '',
            Base64UrlSafe::encodeUnpadded($iv),
            Base64UrlSafe::encodeUnpadded($ciphertext),
            Base64UrlSafe::encodeUnpadded($tag ?? ''),
        ]));
        $decrypter = new JWEDecrypter(new AlgorithmManager([
            self::keyAgreementReturning($cek),
            new A256CBCHS512(),
        ]), null);

        static::assertFalse($decrypter->decryptUsingKey($jwe, new JWK(self::RECIPIENT_KEY), 0));
    }

    private static function keyAgreementReturning(string $key): KeyAgreement
    {
        return new class($key) implements KeyAgreement {
            public function __construct(
                private readonly string $key
            ) {
            }

            public function name(): string
            {
                return 'ECDH-ES';
            }

            public function allowedKeyTypes(): array
            {
                return ['EC'];
            }

            public function getKeyManagementMode(): string
            {
                return self::MODE_AGREEMENT;
            }

            public function getAgreementKey(
                int $encryptionKeyLength,
                string $algorithm,
                JWK $recipientKey,
                ?JWK $senderKey,
                array $completeHeader = [],
                array &$additionalHeaderValues = []
            ): string {
                return $this->key;
            }
        };
    }
}

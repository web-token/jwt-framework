<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\OKPKey;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\AbstractHPKE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\AbstractHPKEKE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE0;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE0KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE1;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE1KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE2;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE2KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE3;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE3KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE4;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE5;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE5KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE6;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE7;
use Jose\Component\Encryption\Algorithm\KeyEncryption\HPKE7KE;
use Jose\Component\Encryption\Algorithm\KeyEncryption\IntegratedEncryption;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Recipient;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;
use function count;
use function in_array;
use function sprintf;
use function str_ends_with;

/**
 * HPKE in JWE (draft-ietf-jose-hpke-encrypt-22): Integrated Encryption, where HPKE encrypts the payload itself, and
 * Key Encryption, where HPKE encrypts the CEK of a regular content encryption algorithm.
 *
 * @internal
 */
final class HPKEEncryptionTest extends TestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    /**
     * The algorithm of each identifier and the curve of the keys it accepts.
     *
     * @var array<string, array{class-string<AbstractHPKE|AbstractHPKEKE>, string}>
     */
    private const ALGORITHMS = [
        'HPKE-0' => [HPKE0::class, 'P-256'],
        'HPKE-1' => [HPKE1::class, 'P-384'],
        'HPKE-2' => [HPKE2::class, 'P-521'],
        'HPKE-3' => [HPKE3::class, 'X25519'],
        'HPKE-4' => [HPKE4::class, 'X25519'],
        'HPKE-5' => [HPKE5::class, 'X448'],
        'HPKE-6' => [HPKE6::class, 'X448'],
        'HPKE-7' => [HPKE7::class, 'P-256'],
        'HPKE-0-KE' => [HPKE0KE::class, 'P-256'],
        'HPKE-1-KE' => [HPKE1KE::class, 'P-384'],
        'HPKE-2-KE' => [HPKE2KE::class, 'P-521'],
        'HPKE-3-KE' => [HPKE3KE::class, 'X25519'],
        'HPKE-5-KE' => [HPKE5KE::class, 'X448'],
        'HPKE-7-KE' => [HPKE7KE::class, 'P-256'],
    ];

    /**
     * @return iterable<string, array{string}>
     */
    public static function integratedEncryptionAlgorithms(): iterable
    {
        foreach (array_keys(self::ALGORITHMS) as $alg) {
            if (! str_ends_with($alg, '-KE')) {
                yield $alg => [$alg];
            }
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function keyEncryptionAlgorithms(): iterable
    {
        foreach (array_keys(self::ALGORITHMS) as $alg) {
            if (str_ends_with($alg, '-KE')) {
                yield $alg => [$alg];
            }
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function allAlgorithms(): iterable
    {
        yield from self::integratedEncryptionAlgorithms();
        yield from self::keyEncryptionAlgorithms();
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function theAlgorithmDescribesItsKeyManagementMode(string $alg): void
    {
        $algorithm = $this->algorithm($alg);

        static::assertSame($alg, $algorithm->name());
        static::assertSame(
            in_array(self::ALGORITHMS[$alg][1], ['X25519', 'X448'], true) ? ['OKP'] : ['EC'],
            $algorithm->allowedKeyTypes()
        );
        if (str_ends_with($alg, '-KE')) {
            static::assertNotInstanceOf(IntegratedEncryption::class, $algorithm);
            static::assertSame(KeyEncryptionAlgorithm::MODE_ENCRYPT, $algorithm->getKeyManagementMode());

            return;
        }
        static::assertInstanceOf(IntegratedEncryption::class, $algorithm);
        static::assertSame(IntegratedEncryption::MODE_INTEGRATED, $algorithm->getKeyManagementMode());
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function theAlgorithmIsAvailableWhenThePlatformCanRunIt(string $alg): void
    {
        [$class, $curve] = self::ALGORITHMS[$alg];
        $chacha20 = in_array($alg, ['HPKE-4', 'HPKE-6'], true);
        $expected = OKPKey::isCurveSupported($curve) || ! in_array($curve, ['X25519', 'X448'], true);
        if ($chacha20) {
            $expected = $expected && in_array('chacha20-poly1305', openssl_get_cipher_methods(), true);
        }

        static::assertSame($expected, $class::isSupported());
        if (! $expected) {
            $this->expectException(MissingDependencyException::class);
            new $class();
        }
    }

    #[Test]
    #[DataProvider('integratedEncryptionAlgorithms')]
    public function anIntegratedEncryptionRoundTrips(string $alg): void
    {
        $key = $this->recipientKey($alg);

        foreach ([['jwe_compact', null], ['jwe_json_flattened', 'AAD'], ['jwe_json_general', null]] as [$serialization, $aad]) {
            $jwe = $this->builder()
                ->withPayload(self::PAYLOAD)
                ->withAAD($aad)
                ->withSharedProtectedHeader([
                    'alg' => $alg,
                ])
                ->addRecipient($key->toPublic())
                ->build();
            $loaded = $this->roundTrip($serialization, $jwe);

            static::assertSame('', $loaded->getIV(), $serialization);
            static::assertSame('', $loaded->getTag(), $serialization);
            static::assertSame(1, $loaded->countRecipients());
            static::assertSame([], $loaded->getRecipient(0)->getHeader());
            static::assertSame([
                'alg' => $alg,
            ], $loaded->getSharedProtectedHeader());
            static::assertSame(self::PAYLOAD, $this->decrypt($loaded, $key)?->getPayload(), $serialization);
        }
    }

    #[Test]
    #[DataProvider('keyEncryptionAlgorithms')]
    public function aKeyEncryptionRoundTrips(string $alg): void
    {
        $key = $this->recipientKey($alg);

        foreach (['A128GCM', 'A256GCM', 'A128CBC-HS256'] as $enc) {
            $jwe = $this->builder()
                ->withPayload(self::PAYLOAD)
                ->withSharedProtectedHeader([
                    'alg' => $alg,
                    'enc' => $enc,
                ])
                ->addRecipient($key->toPublic())
                ->build();
            $loaded = $this->roundTrip('jwe_compact', $jwe);

            static::assertTrue($loaded->hasSharedProtectedHeaderParameter('ek'), $enc);
            static::assertSame(self::PAYLOAD, $this->decrypt($loaded, $key)?->getPayload(), $enc);
        }
    }

    #[Test]
    public function theKeyEncryptionAlgorithmsShareTheContentEncryptionKeyWithOtherRecipients(): void
    {
        $recipients = [
            ['HPKE-0-KE', $this->recipientKey('HPKE-0-KE')],
            ['RSA-OAEP-256', (new JWKFactory())->rsa(2048)],
            ['HPKE-3-KE', $this->recipientKey('HPKE-3-KE')],
        ];
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'enc' => 'A256GCM',
            ]);
        foreach ($recipients as [$alg, $key]) {
            $builder = $builder->addRecipient($key->toPublic(), [
                'alg' => $alg,
            ]);
        }

        $jwe = $this->roundTrip('jwe_json_general', $builder->build());

        static::assertFalse($jwe->hasSharedProtectedHeaderParameter('ek'));
        foreach ($recipients as $index => [$alg, $key]) {
            static::assertSame(
                str_starts_with($alg, 'HPKE'),
                $jwe->getRecipient($index)
                    ->hasHeaderParameter('ek'),
                $alg
            );
            $result = $this->decrypter()
                ->decrypt($jwe, $key, $index);
            static::assertTrue($result->isDecrypted(), $alg);
            static::assertSame(self::PAYLOAD, $result->getJwe()->getPayload());
        }
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function aPreSharedKeyAuthenticatesTheSender(string $alg): void
    {
        $key = $this->recipientKey($alg);
        $psk = $this->preSharedKey('psk-2026');
        $otherPsk = $this->preSharedKey('psk-2026');

        $jwe = $this->roundTrip('jwe_compact', $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader($this->header($alg, [
                'psk_id' => Base64UrlSafe::encodeUnpadded('psk-2026'),
            ]))
            ->withSenderKey($psk)
            ->addRecipient($key->toPublic())
            ->build());

        static::assertSame(self::PAYLOAD, $this->decrypt($jwe, $key, $psk)?->getPayload());
        static::assertNull($this->decrypt($jwe, $key), 'The pre-shared key is required.');
        static::assertNull($this->decrypt($jwe, $key, $otherPsk), 'Another pre-shared key does not decrypt.');
    }

    #[Test]
    #[DataProvider('allAlgorithms')]
    public function aTokenWithoutPreSharedKeyIsRejectedWhenOneIsExpected(string $alg): void
    {
        $key = $this->recipientKey($alg);

        $jwe = $this->roundTrip('jwe_compact', $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader($this->header($alg))
            ->addRecipient($key->toPublic())
            ->build());

        static::assertSame(self::PAYLOAD, $this->decrypt($jwe, $key)?->getPayload());
        static::assertNull($this->decrypt($jwe, $key, $this->preSharedKey('psk-2026')));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>, JWK|null, class-string<Throwable>}>
     */
    public static function invalidPreSharedKeyUsages(): iterable
    {
        $psk = static fn (array $values): JWK => new JWK($values + [
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(str_repeat('k', 32)),
        ]);
        $pskId = [
            'psk_id' => Base64UrlSafe::encodeUnpadded('psk-2026'),
        ];
        foreach (['HPKE-0', 'HPKE-0-KE'] as $alg) {
            yield $alg . ', no identifier' => [$alg, [], $psk([]), InvalidHeaderParameterException::class];
            yield $alg . ', no key' => [$alg, $pskId, null, InvalidKeyException::class];
            yield $alg . ', not a symmetric key' => [
                $alg,
                $pskId,
                (new JWKFactory())->ec('P-256'),
                InvalidKeyException::class,
            ];
            yield $alg . ', too short' => [
                $alg,
                $pskId,
                $psk([
                    'k' => Base64UrlSafe::encodeUnpadded(str_repeat('k', 31)),
                ]),
                InvalidKeyException::class,
            ];
            yield $alg . ', another identifier' => [
                $alg,
                $pskId,
                $psk([
                    'kid' => 'psk-2025',
                ]),
                InvalidKeyException::class,
            ];
            yield $alg . ', not base64url' => [
                $alg,
                [
                    'psk_id' => 'psk.2026',
                ],
                $psk([]),
                InvalidHeaderParameterException::class,
            ];
        }
    }

    /**
     * @param array<string, mixed> $header
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('invalidPreSharedKeyUsages')]
    public function theUseOfThePreSharedKeyIsChecked(string $alg, array $header, ?JWK $psk, string $exception): void
    {
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader($this->header($alg, $header))
            ->addRecipient($this->recipientKey($alg)->toPublic());
        if ($psk !== null) {
            $builder = $builder->withSenderKey($psk);
        }

        $this->expectException($exception);

        $builder->build();
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function substitutions(): iterable
    {
        yield 'HPKE-0 to HPKE-7' => ['HPKE-0', 'HPKE-7'];
        yield 'HPKE-3 to HPKE-4' => ['HPKE-3', 'HPKE-4'];
        yield 'HPKE-0-KE to HPKE-7-KE' => ['HPKE-0-KE', 'HPKE-7-KE'];
    }

    /**
     * The algorithms of each pair share the KEM, hence the key: only the binding of "alg" to the HPKE computation, the
     * associated data in Integrated Encryption and the cipher suite of the key schedule in both modes, tells them
     * apart.
     */
    #[Test]
    #[DataProvider('substitutions')]
    public function aSubstitutedAlgorithmIsNotDecrypted(string $alg, string $substitute): void
    {
        $this->algorithm($substitute);
        $key = $this->recipientKey($alg);
        $compact = $this->serializer()
            ->serialize('jwe_compact', $this->builder()->withPayload(self::PAYLOAD)->withSharedProtectedHeader(
                $this->header($alg)
            )->addRecipient($key->toPublic())->build(), 0);

        $tampered = $this->replaceProtectedHeader($compact, static function (array $header) use ($substitute): array {
            $header['alg'] = $substitute;

            return $header;
        });

        static::assertSame(self::PAYLOAD, $this->decrypt($this->serializer()->unserialize($compact), $key)?->getPayload());
        static::assertNull($this->decrypt($this->serializer()->unserialize($tampered), $key));
    }

    #[Test]
    #[DataProvider('keyEncryptionAlgorithms')]
    public function aSubstitutedEncapsulatedKeyIsNotDecrypted(string $alg): void
    {
        $key = $this->recipientKey($alg);
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader($this->header($alg))
            ->addRecipient($key->toPublic());
        $compact = $this->serializer()
            ->serialize('jwe_compact', $builder->build(), 0);
        $otherJwe = $this->serializer()
            ->unserialize($this->serializer()->serialize('jwe_compact', $builder->build(), 0));

        $tampered = $this->replaceProtectedHeader($compact, static function (array $header) use ($otherJwe): array {
            $header['ek'] = $otherJwe->getSharedProtectedHeaderParameter('ek');

            return $header;
        });

        static::assertNull($this->decrypt($this->serializer()->unserialize($tampered), $key));
    }

    #[Test]
    #[DataProvider('integratedEncryptionAlgorithms')]
    public function theAdditionalAuthenticatedDataAndTheProtectedHeaderAreAuthenticated(string $alg): void
    {
        $key = $this->recipientKey($alg);
        $jwe = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withAAD('AAD')
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'kid' => 'key-1',
            ])
            ->addRecipient($key->toPublic())
            ->build();

        $otherAad = new JWE(
            $jwe->getCiphertext(),
            '',
            '',
            'Another AAD',
            [],
            $jwe->getSharedProtectedHeader(),
            $jwe->getEncodedSharedProtectedHeader(),
            $jwe->getRecipients()
        );
        $header = [
            'alg' => $alg,
            'kid' => 'key-2',
        ];
        $otherHeader = new JWE(
            $jwe->getCiphertext(),
            '',
            '',
            'AAD',
            [],
            $header,
            Base64UrlSafe::encodeUnpadded(JsonConverter::encode($header)),
            $jwe->getRecipients()
        );

        static::assertSame(self::PAYLOAD, $this->decrypt($jwe, $key)?->getPayload());
        static::assertNull($this->decrypt($otherAad, $key));
        static::assertNull($this->decrypt($otherHeader, $key));
    }

    #[Test]
    #[DataProvider('integratedEncryptionAlgorithms')]
    public function theApplicationInformationIsBoundToTheIntegratedEncryption(string $alg): void
    {
        $class = self::ALGORITHMS[$alg][0];
        $key = $this->recipientKey($alg);
        $builder = new JWEBuilder(new AlgorithmManager([new $class('mutually known private information')]));
        $jwe = $builder->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
            ])
            ->addRecipient($key->toPublic())
            ->build();

        $same = (new JWEDecrypter(new AlgorithmManager([new $class('mutually known private information')])))
            ->decrypt($jwe, $key, 0);
        $other = (new JWEDecrypter(new AlgorithmManager([new $class()])))
            ->decrypt($jwe, $key, 0);

        static::assertSame(self::PAYLOAD, $same->getJwe()->getPayload());
        static::assertFalse($other->isDecrypted());
    }

    #[Test]
    #[DataProvider('keyEncryptionAlgorithms')]
    public function theApplicationInformationIsBoundToTheKeyEncryption(string $alg): void
    {
        $class = self::ALGORITHMS[$alg][0];
        $key = $this->recipientKey($alg);
        $builder = new JWEBuilder(new AlgorithmManager([new $class('mutually known private information'), new A128GCM()]));
        $jwe = $builder->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => 'A128GCM',
            ])
            ->addRecipient($key->toPublic())
            ->build();

        $same = (new JWEDecrypter(new AlgorithmManager([
            new $class('mutually known private information'),
            new A128GCM(),
        ])))->decrypt($jwe, $key, 0);
        $other = (new JWEDecrypter(new AlgorithmManager([new $class(), new A128GCM()])))->decrypt($jwe, $key, 0);

        static::assertSame(self::PAYLOAD, $same->getJwe()->getPayload());
        static::assertFalse($other->isDecrypted());
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function contentEncryptionSubstitutions(): iterable
    {
        yield 'A128GCM to A256GCM' => ['HPKE-0-KE', 'A128GCM', 'A256GCM'];
        yield 'A256GCM to A128GCM' => ['HPKE-3-KE', 'A256GCM', 'A128GCM'];
    }

    /**
     * The "enc" header parameter is part of the HPKE info of Key Encryption (the Recipient_structure): a CEK
     * encrypted for one content encryption algorithm is not decrypted for another one. Both algorithms of each pair
     * share the IV size, so that the decryption reaches the encrypted key; without the binding, it would fail later
     * on the size of the CEK.
     */
    #[Test]
    #[DataProvider('contentEncryptionSubstitutions')]
    public function theContentEncryptionAlgorithmIsBoundToTheEncryptedKey(string $alg, string $enc, string $other): void
    {
        $key = $this->recipientKey($alg);
        $jwe = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => $enc,
            ])
            ->addRecipient($key->toPublic())
            ->build();
        $ek = $jwe->getSharedProtectedHeaderParameter('ek');
        $failures = [];

        $substituted = new JWE(
            $jwe->getCiphertext(),
            $jwe->getIV() ?? '',
            $jwe->getTag() ?? '',
            null,
            [],
            [
                'enc' => $other,
            ],
            Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                'enc' => $other,
            ])),
            [new Recipient([
                'alg' => $alg,
                'ek' => $ek,
            ], $jwe->getRecipient(0)->getEncryptedKey())]
        );
        $result = $this->decrypter()
            ->decrypt($substituted, $key, 0, null, static function (Throwable $throwable) use (&$failures): void {
                $failures[] = $throwable;
            });

        static::assertFalse($result->isDecrypted());
        static::assertCount(1, $failures);
        static::assertStringContainsString('decrypt', $failures[0]->getMessage());
    }

    #[Test]
    #[DataProvider('integratedEncryptionAlgorithms')]
    public function anIntegratedEncryptionIsBuiltWithoutContentEncryptionAlgorithm(string $alg): void
    {
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => 'A128GCM',
            ])
            ->addRecipient($this->recipientKey($alg)->toPublic());

        $this->expectException(InvalidHeaderParameterException::class);
        $this->expectExceptionMessage('"enc"');

        $builder->build();
    }

    #[Test]
    public function anIntegratedEncryptionIsBuiltForASingleRecipient(): void
    {
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'HPKE-0',
            ])
            ->addRecipient($this->recipientKey('HPKE-0')->toPublic())
            ->addRecipient($this->recipientKey('HPKE-0')->toPublic());

        $this->expectException(LogicException::class);

        $builder->build();
    }

    #[Test]
    public function anIntegratedEncryptionIsNotMixedWithAnotherKeyManagementMode(): void
    {
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'enc' => 'A128GCM',
            ])
            ->addRecipient($this->recipientKey('HPKE-0-KE')->toPublic(), [
                'alg' => 'HPKE-0-KE',
            ])
            ->addRecipient($this->recipientKey('HPKE-0')->toPublic(), [
                'alg' => 'HPKE-0',
            ]);

        $this->expectException(LogicException::class);

        $builder->build();
    }

    #[Test]
    public function theIntegratedEncryptionAlgorithmIsProtected(): void
    {
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'kid' => 'key-1',
            ])
            ->addRecipient($this->recipientKey('HPKE-0')->toPublic(), [
                'alg' => 'HPKE-0',
            ]);

        $this->expectException(InvalidHeaderParameterException::class);
        $this->expectExceptionMessage('"alg"');

        $builder->build();
    }

    #[Test]
    #[DataProvider('keyEncryptionAlgorithms')]
    public function aKeyEncryptionNeedsAContentEncryptionAlgorithm(string $alg): void
    {
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
            ])
            ->addRecipient($this->recipientKey($alg)->toPublic());

        $this->expectException(InvalidHeaderParameterException::class);
        $this->expectExceptionMessage('"enc"');

        $builder->build();
    }

    /**
     * @return iterable<string, array{callable(JWE): JWE, class-string<Throwable>}>
     */
    public static function malformedIntegratedEncryptions(): iterable
    {
        yield 'with a content encryption algorithm' => [
            static fn (JWE $jwe): JWE => self::withProtectedHeader($jwe, [
                'alg' => 'HPKE-0',
                'enc' => 'A128GCM',
            ]),
            InvalidHeaderParameterException::class,
        ];
        yield 'with the algorithm in the recipient header' => [
            static fn (JWE $jwe): JWE => new JWE(
                $jwe->getCiphertext(),
                '',
                '',
                null,
                [],
                [
                    'kid' => 'key-1',
                ],
                Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                    'kid' => 'key-1',
                ])),
                [new Recipient([
                    'alg' => 'HPKE-0',
                ], $jwe->getRecipient(0)->getEncryptedKey())]
            ),
            InvalidHeaderParameterException::class,
        ];
        yield 'with two recipients' => [
            static fn (JWE $jwe): JWE => new JWE(
                $jwe->getCiphertext(),
                '',
                '',
                null,
                [],
                $jwe->getSharedProtectedHeader(),
                $jwe->getEncodedSharedProtectedHeader(),
                [$jwe->getRecipient(0), $jwe->getRecipient(0)]
            ),
            InvalidArgumentException::class,
        ];
        yield 'with an initialization vector' => [
            static fn (JWE $jwe): JWE => new JWE(
                $jwe->getCiphertext(),
                random_bytes(12),
                '',
                null,
                [],
                $jwe->getSharedProtectedHeader(),
                $jwe->getEncodedSharedProtectedHeader(),
                $jwe->getRecipients()
            ),
            InvalidArgumentException::class,
        ];
        yield 'with an authentication tag' => [
            static fn (JWE $jwe): JWE => new JWE(
                $jwe->getCiphertext(),
                '',
                random_bytes(16),
                null,
                [],
                $jwe->getSharedProtectedHeader(),
                $jwe->getEncodedSharedProtectedHeader(),
                $jwe->getRecipients()
            ),
            InvalidArgumentException::class,
        ];
        yield 'without encrypted key' => [
            static fn (JWE $jwe): JWE => new JWE(
                $jwe->getCiphertext(),
                '',
                '',
                null,
                [],
                $jwe->getSharedProtectedHeader(),
                $jwe->getEncodedSharedProtectedHeader(),
                [new Recipient([], null)]
            ),
            InvalidArgumentException::class,
        ];
    }

    /**
     * @param callable(JWE): JWE $alter
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('malformedIntegratedEncryptions')]
    public function aMalformedIntegratedEncryptionIsRejected(callable $alter, string $exception): void
    {
        $key = $this->recipientKey('HPKE-0');
        $jwe = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'HPKE-0',
            ])
            ->addRecipient($key->toPublic())
            ->build();

        $this->expectException($exception);

        $this->decrypter()
            ->decrypt($alter($jwe), $key, 0);
    }

    /**
     * The "ek" header parameter belongs to Key Encryption: its presence is checked by the algorithm, like the other
     * algorithm-specific header parameters, so the key is discarded and the failure reported.
     */
    #[Test]
    public function anIntegratedEncryptionWithAnEncapsulatedKeyHeaderParameterIsNotDecrypted(): void
    {
        $key = $this->recipientKey('HPKE-0');
        $jwe = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'HPKE-0',
            ])
            ->addRecipient($key->toPublic())
            ->build();
        $failures = [];

        $result = $this->decrypter()
            ->decrypt(self::withProtectedHeader($jwe, [
                'alg' => 'HPKE-0',
                'ek' => Base64UrlSafe::encodeUnpadded($jwe->getRecipient(0)->getEncryptedKey() ?? ''),
            ]), $key, 0, null, static function (Throwable $throwable) use (&$failures): void {
                $failures[] = $throwable;
            });

        static::assertFalse($result->isDecrypted());
        static::assertCount(1, $failures);
        static::assertInstanceOf(InvalidHeaderParameterException::class, $failures[0]);
    }

    #[Test]
    public function anIntegratedEncryptionIsNotBuiltWithAnEncapsulatedKeyHeaderParameter(): void
    {
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'HPKE-0',
                'ek' => 'BA',
            ])
            ->addRecipient($this->recipientKey('HPKE-0')->toPublic());

        $this->expectException(InvalidHeaderParameterException::class);

        $builder->build();
    }

    #[Test]
    #[DataProvider('keyEncryptionAlgorithms')]
    public function aKeyEncryptionIsNotBuiltWithAnEncapsulatedKeyHeaderParameter(string $alg): void
    {
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader($this->header($alg, [
                'ek' => 'BA',
            ]))
            ->addRecipient($this->recipientKey($alg)->toPublic());

        $this->expectException(InvalidHeaderParameterException::class);

        $builder->build();
    }

    #[Test]
    #[DataProvider('keyEncryptionAlgorithms')]
    public function aKeyEncryptionWithoutContentEncryptionAlgorithmIsRejected(string $alg): void
    {
        $key = $this->recipientKey($alg);
        $jwe = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader($this->header($alg))
            ->addRecipient($key->toPublic())
            ->build();
        $header = $jwe->getSharedProtectedHeader();
        unset($header['enc']);

        $this->expectException(InvalidHeaderParameterException::class);

        $this->decrypter()
            ->decrypt(self::withProtectedHeader($jwe, $header), $key, 0);
    }

    #[Test]
    #[DataProvider('keyEncryptionAlgorithms')]
    public function aKeyEncryptionWithoutEncapsulatedKeyIsNotDecrypted(string $alg): void
    {
        $key = $this->recipientKey($alg);
        $jwe = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader($this->header($alg))
            ->addRecipient($key->toPublic())
            ->build();
        $header = $jwe->getSharedProtectedHeader();
        unset($header['ek']);

        static::assertNull($this->decrypt(self::withProtectedHeader($jwe, $header), $key));
    }

    /**
     * @return iterable<string, array{string, JWK}>
     */
    public static function unsuitableKeys(): iterable
    {
        $factory = new JWKFactory();

        yield 'HPKE-0 with a P-384 key' => ['HPKE-0', $factory->ec('P-384')];
        yield 'HPKE-0-KE with a P-521 key' => ['HPKE-0-KE', $factory->ec('P-521')];
        yield 'HPKE-3 with a P-256 key' => ['HPKE-3', $factory->ec('P-256')];
        yield 'HPKE-3-KE with an Ed25519 key' => ['HPKE-3-KE', $factory->okp('Ed25519')];
        yield 'HPKE-0 with a key for HPKE-7' => ['HPKE-0', $factory->ec('P-256', [
            'alg' => 'HPKE-7',
        ])];
        yield 'HPKE-7 with an RSA key' => ['HPKE-7', $factory->rsa(2048)];
    }

    #[Test]
    #[DataProvider('unsuitableKeys')]
    public function anUnsuitableRecipientKeyIsRejected(string $alg, JWK $key): void
    {
        $this->algorithm($alg);
        $builder = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader($this->header($alg))
            ->addRecipient($key->toPublic());

        $this->expectException(InvalidKeyException::class);

        $builder->build();
    }

    /**
     * The loader runs the header checkers before the decrypter: an application restricts the algorithms it accepts
     * there, as for any other algorithm.
     */
    #[Test]
    #[DataProvider('allAlgorithms')]
    public function theLoaderLoadsAndDecryptsTheToken(string $alg): void
    {
        $key = $this->recipientKey($alg);
        $token = $this->serializer()
            ->serialize('jwe_compact', $this->builder()->withPayload(self::PAYLOAD)->withSharedProtectedHeader(
                $this->header($alg)
            )->addRecipient($key->toPublic())->build(), 0);
        $loader = fn (string $accepted): JWELoader => new JWELoader(
            $this->serializer(),
            $this->decrypter(),
            new HeaderCheckerManager([new AlgorithmChecker([$accepted], true)], [new JWETokenSupport()])
        );

        $result = $loader($alg)->loadAndDecrypt($token, $key);

        static::assertSame(self::PAYLOAD, $result->getJwe()->getPayload());
        $this->expectException(InvalidTokenException::class);
        $loader('RSA-OAEP-256')->loadAndDecrypt($token, $key);
    }

    #[Test]
    public function theJsonSerializationsOmitTheEmptyInitializationVectorAndTag(): void
    {
        $jwe = $this->builder()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'HPKE-0',
            ])
            ->addRecipient($this->recipientKey('HPKE-0')->toPublic())
            ->build();

        foreach (['jwe_json_flattened', 'jwe_json_general'] as $serialization) {
            $members = JsonConverter::decode($this->serializer()->serialize($serialization, $jwe, 0));
            static::assertIsArray($members);
            static::assertArrayNotHasKey('iv', $members, $serialization);
            static::assertArrayNotHasKey('tag', $members, $serialization);
            static::assertArrayHasKey('ciphertext', $members, $serialization);
        }
    }

    /**
     * @param array<string, mixed> $header
     */
    private static function withProtectedHeader(JWE $jwe, array $header): JWE
    {
        return new JWE(
            $jwe->getCiphertext(),
            $jwe->getIV() ?? '',
            $jwe->getTag() ?? '',
            $jwe->getAAD(),
            $jwe->getSharedHeader(),
            $header,
            Base64UrlSafe::encodeUnpadded(JsonConverter::encode($header)),
            $jwe->getRecipients()
        );
    }

    /**
     * @param callable(array<string, mixed>): array<string, mixed> $alter
     */
    private function replaceProtectedHeader(string $compact, callable $alter): string
    {
        $parts = explode('.', $compact);
        $header = JsonConverter::decode(Base64UrlSafe::decodeNoPadding($parts[0]));
        static::assertIsArray($header);
        $parts[0] = Base64UrlSafe::encodeUnpadded(JsonConverter::encode($alter($header)));

        return implode('.', $parts);
    }

    /**
     * @param array<string, mixed> $additionalParameters
     * @return array<string, mixed>
     */
    private function header(string $alg, array $additionalParameters = []): array
    {
        $header = [
            'alg' => $alg,
        ];
        if (str_ends_with($alg, '-KE')) {
            $header['enc'] = 'A128GCM';
        }

        return $header + $additionalParameters;
    }

    private function decrypt(JWE $jwe, JWK $key, ?JWK $senderKey = null): ?JWE
    {
        $result = $this->decrypter()
            ->decrypt($jwe, $key, 0, $senderKey);

        return $result->isDecrypted() ? $result->getJwe() : null;
    }

    private function roundTrip(string $serialization, JWE $jwe): JWE
    {
        return $this->serializer()
            ->unserialize($this->serializer()->serialize($serialization, $jwe, 0));
    }

    private function recipientKey(string $alg): JWK
    {
        $this->algorithm($alg);
        $curve = self::ALGORITHMS[$alg][1];
        $factory = new JWKFactory();

        return in_array($curve, ['X25519', 'X448'], true) ? $factory->okp($curve) : $factory->ec($curve);
    }

    private function preSharedKey(string $kid): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'kid' => $kid,
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
    }

    private function algorithm(string $alg): KeyEncryptionAlgorithm
    {
        $class = self::ALGORITHMS[$alg][0];
        if (! $class::isSupported()) {
            static::markTestSkipped(sprintf('The algorithm "%s" is not available on this platform.', $alg));
        }

        return new $class();
    }

    private function algorithmManager(): AlgorithmManager
    {
        $algorithms = [new A128GCM(), new A256GCM(), new A128CBCHS256(), new RSAOAEP256()];
        foreach (self::ALGORITHMS as [$class]) {
            if ($class::isSupported()) {
                $algorithms[] = new $class();
            }
        }
        static::assertGreaterThan(4, count($algorithms));

        return new AlgorithmManager($algorithms);
    }

    private function builder(): JWEBuilder
    {
        return new JWEBuilder($this->algorithmManager());
    }

    private function decrypter(): JWEDecrypter
    {
        return new JWEDecrypter($this->algorithmManager());
    }

    private function serializer(): JWESerializerManager
    {
        return new JWESerializerManager([
            new CompactSerializer(),
            new JSONFlattenedSerializer(),
            new JSONGeneralSerializer(),
        ]);
    }
}

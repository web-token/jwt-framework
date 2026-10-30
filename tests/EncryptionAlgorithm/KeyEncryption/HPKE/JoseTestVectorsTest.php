<?php

declare(strict_types=1);

namespace Jose\Tests\EncryptionAlgorithm\KeyEncryption\HPKE;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
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
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function json_encode;
use function sprintf;
use function str_ends_with;
use function strlen;
use const JSON_THROW_ON_ERROR;

/**
 * The test vectors of draft-ietf-jose-hpke-encrypt-22 appendix A: one private key, one JWE JSON Serialization with
 * additional authenticated data and one JWE Compact Serialization per algorithm.
 *
 * The vectors come from the examples/jose-vectors.json file of the working group repository at the
 * draft-ietf-jose-hpke-encrypt-22 tag, without the HPKE-4-KE and HPKE-6-KE entries the -22 revision removed from the
 * registry. The plaintext and the additional authenticated data are those of the scripts/jwe.js script that produced
 * them. The CEK, the IV and the ephemeral keys were random and are not published: the vectors are decrypted, and a
 * new token is built for the same key and decrypted in turn.
 *
 * @internal
 */
final class JoseTestVectorsTest extends TestCase
{
    private const PLAINTEXT = 'You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.';

    private const AAD = 'The Fellowship of the Ring';

    /**
     * @var array<string, class-string<AbstractHPKE|AbstractHPKEKE>>
     */
    private const ALGORITHMS = [
        'HPKE-0' => HPKE0::class,
        'HPKE-1' => HPKE1::class,
        'HPKE-2' => HPKE2::class,
        'HPKE-3' => HPKE3::class,
        'HPKE-4' => HPKE4::class,
        'HPKE-5' => HPKE5::class,
        'HPKE-6' => HPKE6::class,
        'HPKE-7' => HPKE7::class,
        'HPKE-0-KE' => HPKE0KE::class,
        'HPKE-1-KE' => HPKE1KE::class,
        'HPKE-2-KE' => HPKE2KE::class,
        'HPKE-3-KE' => HPKE3KE::class,
        'HPKE-5-KE' => HPKE5KE::class,
        'HPKE-7-KE' => HPKE7KE::class,
    ];

    /**
     * The size in bytes of the encapsulated key of each KEM.
     */
    private const ENCAPSULATED_KEY_SIZES = [
        'P-256' => 65,
        'P-384' => 97,
        'P-521' => 133,
        'X25519' => 32,
        'X448' => 56,
    ];

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function vectors(): iterable
    {
        $vectors = json_decode(
            (string) file_get_contents(__DIR__ . '/../../../fixtures/draft-ietf-jose-hpke-encrypt-22/jose-vectors.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        foreach ($vectors as $vector) {
            yield $vector['alg'] => [$vector];
        }
    }

    #[Test]
    public function everyRegisteredAlgorithmHasAVector(): void
    {
        $expected = array_keys(self::ALGORITHMS);
        $algorithms = array_keys(iterator_to_array(self::vectors()));
        sort($expected);
        sort($algorithms);

        static::assertSame($expected, $algorithms);
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function theCompactSerializationIsDecrypted(array $vector): void
    {
        $decrypter = new JWEDecrypter($this->algorithmManager($vector['alg']));
        $jwe = $this->serializer()
            ->unserialize($vector['compact']);

        $result = $decrypter->decrypt($jwe, new JWK($vector['jwk']), 0);

        static::assertTrue($result->isDecrypted());
        static::assertSame(self::PLAINTEXT, $result->getJwe()->getPayload());
        $this->assertStructure($vector, $jwe);
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function theJsonSerializationIsDecrypted(array $vector): void
    {
        $decrypter = new JWEDecrypter($this->algorithmManager($vector['alg']));
        $jwe = $this->serializer()
            ->unserialize(json_encode($vector['flattened'], JSON_THROW_ON_ERROR));

        $result = $decrypter->decrypt($jwe, new JWK($vector['jwk']), 0);

        static::assertTrue($result->isDecrypted());
        static::assertSame(self::PLAINTEXT, $result->getJwe()->getPayload());
        static::assertSame(self::AAD, $jwe->getAAD());
        $this->assertStructure($vector, $jwe);
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('vectors')]
    public function aTokenBuiltForTheKeyOfTheVectorIsDecrypted(array $vector): void
    {
        $alg = $vector['alg'];
        $algorithmManager = $this->algorithmManager($alg);
        $builder = new JWEBuilder($algorithmManager);
        $decrypter = new JWEDecrypter($algorithmManager);
        $key = new JWK($vector['jwk']);
        $header = [
            'alg' => $alg,
            'kid' => $key->get('kid'),
        ];
        if (str_ends_with($alg, '-KE')) {
            $header['enc'] = $this->contentEncryptionAlgorithmOf($vector);
        }

        foreach (['jwe_compact', 'jwe_json_flattened'] as $serialization) {
            $jwe = $builder
                ->withPayload(self::PLAINTEXT)
                ->withAAD($serialization === 'jwe_compact' ? null : self::AAD)
                ->withSharedProtectedHeader($header)
                ->addRecipient($key->toPublic())
                ->build();
            $loaded = $this->serializer()
                ->unserialize($this->serializer()->serialize($serialization, $jwe, 0));

            $result = $decrypter->decrypt($loaded, $key, 0);

            static::assertTrue($result->isDecrypted(), $serialization);
            static::assertSame(self::PLAINTEXT, $result->getJwe()->getPayload());
            $this->assertStructure($vector, $loaded);
        }
    }

    /**
     * The structure the draft requires: in Integrated Encryption the encrypted key is the encapsulated key and there
     * is neither "enc", nor "ek", nor IV, nor tag; in Key Encryption the encapsulated key is the "ek" header parameter
     * and the encrypted key is the CEK followed by the 16-byte tag of the HPKE AEAD.
     *
     * @param array<string, mixed> $vector
     */
    private function assertStructure(array $vector, JWE $jwe): void
    {
        $encapsulatedKeySize = self::ENCAPSULATED_KEY_SIZES[$vector['jwk']['crv']];
        $encryptedKey = $jwe->getRecipient(0)
            ->getEncryptedKey();
        static::assertIsString($encryptedKey);
        if (! str_ends_with($vector['alg'], '-KE')) {
            static::assertSame($encapsulatedKeySize, strlen($encryptedKey));
            static::assertSame('', $jwe->getIV());
            static::assertSame('', $jwe->getTag());
            static::assertFalse($jwe->hasSharedProtectedHeaderParameter('enc'));
            static::assertFalse($jwe->hasSharedProtectedHeaderParameter('ek'));

            return;
        }
        $ek = $jwe->getSharedProtectedHeaderParameter('ek');
        static::assertIsString($ek);
        static::assertSame($encapsulatedKeySize, strlen(Base64UrlSafe::decodeNoPadding($ek)));
        $cekSize = $jwe->getSharedProtectedHeaderParameter('enc') === 'A128GCM' ? 16 : 32;
        static::assertSame($cekSize + 16, strlen($encryptedKey));
    }

    /**
     * @param array<string, mixed> $vector
     */
    private function contentEncryptionAlgorithmOf(array $vector): string
    {
        $header = json_decode(
            Base64UrlSafe::decodeNoPadding($vector['flattened']['protected']),
            true,
            512,
            JSON_THROW_ON_ERROR
        );

        return $header['enc'];
    }

    private function algorithmManager(string $alg): AlgorithmManager
    {
        $class = self::ALGORITHMS[$alg];
        if (! $class::isSupported()) {
            static::markTestSkipped(sprintf('The algorithm "%s" is not available on this platform.', $alg));
        }

        return new AlgorithmManager([new $class(), new A128GCM(), new A256GCM()]);
    }

    private function serializer(): JWESerializerManager
    {
        return new JWESerializerManager([new CompactSerializer(), new JSONFlattenedSerializer()]);
    }
}

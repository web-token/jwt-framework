<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\AESCBCHS;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function chr;

/**
 * When a JWE has an "aad" member, the additional authenticated data of AES-CBC-HMAC is the encoded protected header, a
 * period and the encoded "aad" member, and AL is the length of that whole value (RFC 7516 section 5.1, RFC 7518
 * section 5.2.2.1).
 *
 * @internal
 */
final class AESCBCHSAdditionalAuthenticatedDataTest extends TestCase
{
    private const KEY = [
        'kty' => 'oct',
        'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
    ];

    private const PAYLOAD = 'Live long and prosper.';

    private const AAD = 'The second principle of Auguste Kerckhoffs';

    /**
     * The content encryption keys and the IV are the ones of RFC 7518 appendix B. The expected values were computed
     * with the Python "cryptography" package; panva/jose 6.2.2 gives the same ones.
     */
    #[Test]
    #[DataProvider('knownAnswers')]
    public function theTagCoversTheWholeAdditionalAuthenticatedData(
        AESCBCHS $algorithm,
        string $protectedHeader,
        string $expectedCiphertext,
        string $expectedTag
    ): void {
        $cek = implode('', array_map(chr(...), range(0, $algorithm->getCEKSize() / 8 - 1)));
        $iv = hex2bin('1af38c2dc2b96ffdd86694092341bc04');
        $tag = null;

        $ciphertext = $algorithm->encryptContent(self::PAYLOAD, $cek, $iv, self::AAD, $protectedHeader, $tag);

        static::assertSame($expectedCiphertext, Base64UrlSafe::encodeUnpadded($ciphertext));
        static::assertSame($expectedTag, Base64UrlSafe::encodeUnpadded((string) $tag));
        static::assertSame(
            self::PAYLOAD,
            $algorithm->decryptContent($ciphertext, $cek, $iv, self::AAD, $protectedHeader, (string) $tag)
        );
    }

    /**
     * @return iterable<string, array{AESCBCHS, string, string, string}>
     */
    public static function knownAnswers(): iterable
    {
        yield 'A128CBC-HS256' => [
            new A128CBCHS256(),
            'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
            'pcgo91p9VhfV6FDsZ3OdW7D89ebbdwU-fxd3HFaNOpQ',
            'UVKjQfACtTRvhSYw8NkV7A',
        ];
        yield 'A192CBC-HS384' => [
            new A192CBCHS384(),
            'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0',
            'p5kn1IaeAPZfYPWqWKWVk-XGdBbJG595m0RHkS-M9f4',
            'e2wZ8gLH-YCIAioiTmWBiIAj3UPYoxYq',
        ];
        yield 'A256CBC-HS512' => [
            new A256CBCHS512(),
            'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0',
            '5o1SizKSWBdQXkkKxUzQxHC8--RelcY4DPItJ37zeSc',
            'KJKEt8U_E6iPdlKh8RDKfhukeO0VONfPwLPUZO36Ra4',
        ];
    }

    /**
     * The tokens were produced by panva/jose 6.2.2 for that key, with that additional authenticated data.
     */
    #[Test]
    #[DataProvider('tokensFromAnotherImplementation')]
    public function aTokenProducedByAnotherImplementationIsDecrypted(JWESerializer $serializer, string $token): void
    {
        $result = $this->decrypter()
            ->decrypt($serializer->unserialize($token), new JWK(self::KEY), 0);

        static::assertTrue($result->isDecrypted());
        static::assertSame(self::AAD, $result->getJwe()->getAAD());
        static::assertSame(self::PAYLOAD, $result->getJwe()->getPayload());
    }

    /**
     * @return iterable<string, array{JWESerializer, string}>
     */
    public static function tokensFromAnotherImplementation(): iterable
    {
        yield 'flattened, A128CBC-HS256' => [
            new JSONFlattenedSerializer(),
            '{"ciphertext":"Helic0fCWyUeU_RcytwgmEaZkL7iJm2ixqxRXAWJDKw","iv":"G80uuoUwVErGhYmecj3RUA","tag":"3hvde7Oo6-K1taY6Ctl40g","encrypted_key":"cDIWBZX1bJeCTHZVR3hG921gtyf3EIQD7KDvn5BKiV5x9igTv_xm0A","aad":"VGhlIHNlY29uZCBwcmluY2lwbGUgb2YgQXVndXN0ZSBLZXJja2hvZmZz","protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"}',
        ];
        yield 'flattened, A192CBC-HS384' => [
            new JSONFlattenedSerializer(),
            '{"ciphertext":"zKyklHKMpFy8AB0C2wqoR6LnOgz_6mze2mjQ0tEZ5II","iv":"2irTlyH4zYWicHbTD672BA","tag":"H0cQULAs8U9RIF_f-ngh8JZPL1TtiMvC","encrypted_key":"tnDEH3gvasMB16YZFQtEpRfWZKn_Irtbqxcd3xcYpdM2zpfqiuj7QNtyEvw-Ll3FdYV-iEvJc3Q","aad":"VGhlIHNlY29uZCBwcmluY2lwbGUgb2YgQXVndXN0ZSBLZXJja2hvZmZz","protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0"}',
        ];
        yield 'flattened, A256CBC-HS512' => [
            new JSONFlattenedSerializer(),
            '{"ciphertext":"5i1Fn0zC5q4F52Oa7AVPfam6A7zuex7AAiQGRrFf5SE","iv":"e5kMUkO-xWbZZUG-FJu1IQ","tag":"FpUsuKd8gqlSM-SHMQoDJfZGow4cKU4m5gh68ZK155Y","encrypted_key":"9UXmN-x2CD2HzfYjJmWMNRdtT0ZWX4eb099q36yvQeI8tKDf2es7r5wOQn6Bku-NPGOgeptwxrtVccr9QGhW1SZuGR2vVQSB","aad":"VGhlIHNlY29uZCBwcmluY2lwbGUgb2YgQXVndXN0ZSBLZXJja2hvZmZz","protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0"}',
        ];
        yield 'general, A128CBC-HS256' => [
            new JSONGeneralSerializer(),
            '{"ciphertext":"rsbSKAcNnH0ZpcL2B_4ly93vS1UBlxfLmLP4nuLPNiA","iv":"brOcmVHJ5KO_cgwF_FZUHA","recipients":[{"encrypted_key":"OmX9NUxCXkol1PcqY-ERo3cxwlnnnOnrCtAesbmtTyLifeokENK91g","header":{"alg":"A128KW"}}],"tag":"zmKa199rqIqOSUjYTbX37A","aad":"VGhlIHNlY29uZCBwcmluY2lwbGUgb2YgQXVndXN0ZSBLZXJja2hvZmZz","protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"}',
        ];
    }

    /**
     * Moving the end of the additional authenticated data into the IV, and the IV into the ciphertext, leaves the input
     * of the MAC unchanged: only AL tells where the additional authenticated data stops. The moved length is a
     * multiple of the block size, so that the original ciphertext still decrypts after the moved blocks.
     */
    #[Test]
    #[DataProvider('movedBoundaries')]
    public function theEndOfTheAdditionalAuthenticatedDataCannotBeMovedIntoTheIV(string $aad, int $movedLength): void
    {
        $key = new JWK(self::KEY);
        $serializer = new JSONFlattenedSerializer();
        $token = $serializer->serialize((new JWEBuilder($this->algorithmManager()))
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128CBC-HS256',
            ])
            ->withAAD($aad)
            ->addRecipient($key)
            ->build(), 0);
        $data = json_decode($token, true);
        $afterHeader = '.' . $data['aad'];
        $blocks = substr($afterHeader, -$movedLength)
            . Base64UrlSafe::decodeNoPadding($data['iv'])
            . Base64UrlSafe::decodeNoPadding($data['ciphertext']);
        $data['iv'] = Base64UrlSafe::encodeUnpadded(substr($blocks, 0, 16));
        $data['ciphertext'] = Base64UrlSafe::encodeUnpadded(substr($blocks, 16));
        $data['aad'] = substr($afterHeader, 1, -$movedLength);
        if ($data['aad'] === '') {
            unset($data['aad']);
        }

        static::assertTrue($this->decrypter()->decrypt($serializer->unserialize($token), $key, 0)->isDecrypted());
        static::assertFalse(
            $this->decrypter()
                ->decrypt($serializer->unserialize(json_encode($data)), $key, 0)
                ->isDecrypted()
        );
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function movedBoundaries(): iterable
    {
        yield 'the last 16 characters of the "aad" member' => [self::AAD, 16];
        yield 'the whole "aad" member and the period' => ['A JWE AAD that is thirty-five bytes', 48];
    }

    private function algorithmManager(): AlgorithmManager
    {
        return new AlgorithmManager([new A128KW(), new A128CBCHS256(), new A192CBCHS384(), new A256CBCHS512()]);
    }

    private function decrypter(): JWEDecrypter
    {
        return new JWEDecrypter($this->algorithmManager());
    }
}

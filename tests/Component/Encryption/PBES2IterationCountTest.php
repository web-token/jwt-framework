<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use ArrayObject;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2AESKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use stdClass;

/**
 * @internal
 */
final class PBES2IterationCountTest extends EncryptionTestCase
{
    #[Test]
    public function recipientsAtTheCapDoNotMultiplyTheDerivations(): void
    {
        $calls = new ArrayObject();
        $jweLoader = new JWELoader(
            $this->getJWESerializerManager(),
            new JWEDecrypter(new AlgorithmManager([
                new CountingPBES2HS256A128KW($calls, PBES2AESKW::DEFAULT_MAX_COUNT),
                new A128GCM(),
            ]), null),
            null
        );
        $token = JsonConverter::encode([
            'protected' => Base64UrlSafe::encodeUnpadded(JsonConverter::encode([
                'alg' => 'PBES2-HS256+A128KW',
                'enc' => 'A128GCM',
                'p2c' => PBES2AESKW::DEFAULT_MAX_COUNT,
                'p2s' => Base64UrlSafe::encodeUnpadded('saltsalt'),
            ])),
            'iv' => Base64UrlSafe::encodeUnpadded(str_repeat("\0", 12)),
            'ciphertext' => Base64UrlSafe::encodeUnpadded('anything'),
            'tag' => Base64UrlSafe::encodeUnpadded(str_repeat("\0", 16)),
            'recipients' => array_fill(0, 30, new stdClass()),
        ]);

        try {
            $jweLoader->loadAndDecryptWithKey($token, $this->createPassword(), $recipient);
        } catch (RuntimeException $exception) {
            static::assertSame('Unable to load and decrypt the token.', $exception->getMessage());
            static::assertCount(0, $calls);

            return;
        }
        static::fail('The token has been decrypted.');
    }

    #[Test]
    public function aTokenForSeveralPasswordsIsDecrypted(): void
    {
        $passwords = [$this->createPassword(), $this->createPassword(), $this->createPassword()];
        $token = $this->createToken(new PBES2HS256A128KW(), $passwords);

        $jwe = $this->getJWELoaderFactory()
            ->create(['jwe_json_general'], ['PBES2-HS256+A128KW', 'A128GCM'])
            ->loadAndDecryptWithKey($token, $passwords[2], $recipient);

        static::assertSame(2, $recipient);
        static::assertSame('Live long and prosper.', $jwe->getPayload());
    }

    #[DataProvider('dataIterationCounts')]
    #[Test]
    public function theRecipientsShareTheCap(int $recipients, int $count, bool $decrypted): void
    {
        $passwords = [];
        for ($i = 0; $i < $recipients; ++$i) {
            $passwords[] = $this->createPassword();
        }
        $token = $this->createToken(new PBES2HS256A128KW(16, $count), $passwords);
        $calls = new ArrayObject();
        $jweDecrypter = new JWEDecrypter(new AlgorithmManager([
            new CountingPBES2HS256A128KW($calls, 10_000),
            new A128GCM(),
        ]), null);
        $jwe = $this->getJWESerializerManager()
            ->unserialize($token);

        static::assertSame(
            $decrypted,
            $jweDecrypter->decryptUsingKey($jwe, $passwords[$recipients - 1], $recipients - 1)
        );
        static::assertCount($decrypted ? 1 : 0, $calls);
    }

    public static function dataIterationCounts(): iterable
    {
        yield 'one recipient at the cap' => [1, 10_000, true];
        yield 'two recipients at half the cap' => [2, 5_000, true];
        yield 'two recipients above half the cap' => [2, 5_001, false];
        yield 'three recipients at a third of the cap' => [3, 3_333, true];
        yield 'three recipients above a third of the cap' => [3, 3_334, false];
    }

    /**
     * @param JWK[] $passwords
     */
    private function createToken(PBES2AESKW $algorithm, array $passwords): string
    {
        $jweBuilder = (new JWEBuilder(new AlgorithmManager([$algorithm, new A128GCM()])))
            ->create()
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'PBES2-HS256+A128KW',
                'enc' => 'A128GCM',
            ]);
        foreach ($passwords as $password) {
            $jweBuilder = $jweBuilder->addRecipient($password);
        }

        return $this->getJWESerializerManager()
            ->serialize('jwe_json_general', $jweBuilder->build());
    }

    private function createPassword(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);
    }
}

<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\Experimental;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Experimental\Signature\Blake2b;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class Blake2bTest extends TestCase
{
    private const string KEY_ONE = 'GOu4rLyVCBxmxP-sbniU68ojAja5PkRdvv7vNvBCqDQ';

    private const string KEY_TWO = 'Pu7gywseH-R5HLIWnMll4rEg1ltjUPq_P9WwEzAsAb8';

    private const string CONTENTS = 'test';

    private const string EXPECTED_HASH_WITH_KEY_ONE = '_TG5kmkav_YGl3I9uQiv4cm1VN6Q0zPCom4G7-p74JU';

    private const string SHORT_KEY = 'PIBQuM5PopdMxtmTWmyvNA';

    private JWK $keyOne;

    private JWK $keyTwo;

    private string $expectedHashWithKeyOne;

    #[Before]
    public function initializeKey(): void
    {
        $this->keyOne = new JWK([
            'kty' => 'oct',
            'k' => self::KEY_ONE,
        ]);
        $this->keyTwo = new JWK([
            'kty' => 'oct',
            'k' => self::KEY_TWO,
        ]);
        $this->expectedHashWithKeyOne = Base64UrlSafe::decode(self::EXPECTED_HASH_WITH_KEY_ONE);
    }

    #[Test]
    public function algorithmIdMustBeCorrect(): void
    {
        $algorithm = new Blake2b();

        static::assertSame('BLAKE2B', $algorithm->name());
    }

    #[Test]
    public function generatedSignatureMustBeSuccessfullyVerified(): void
    {
        $algorithm = new Blake2b();

        static::assertTrue(hash_equals($this->expectedHashWithKeyOne, $algorithm->hash($this->keyOne, self::CONTENTS)));
        static::assertTrue($algorithm->verify($this->keyOne, self::CONTENTS, $this->expectedHashWithKeyOne));
    }

    #[Test]
    public function signShouldRejectShortKeys(): void
    {
        $algorithm = new Blake2b();
        $key = new JWK([
            'kty' => 'oct',
            'k' => self::SHORT_KEY,
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key provided is shorter than 256 bits.');

        $algorithm->hash($key, self::CONTENTS);
    }

    #[Test]
    public function verifyShouldReturnFalseWhenExpectedHashWasNotCreatedWithSameInformation(): void
    {
        $algorithm = new Blake2b();

        static::assertFalse(
            hash_equals($this->expectedHashWithKeyOne, $algorithm->hash($this->keyTwo, self::CONTENTS))
        );
        static::assertFalse($algorithm->verify($this->keyTwo, self::CONTENTS, $this->expectedHashWithKeyOne));
    }
}

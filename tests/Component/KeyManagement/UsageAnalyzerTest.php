<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\Analyzer\Message;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use Jose\Component\KeyManagement\Analyzer\UsageAnalyzer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class UsageAnalyzerTest extends TestCase
{
    private UsageAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new UsageAnalyzer();
    }

    #[Test]
    public function keyWithoutUseShouldGetMediumMessage(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
        ]);

        $bag = new MessageBag();
        $this->analyzer->analyze($jwk, $bag);

        $messages = $bag->all();
        static::assertCount(1, $messages);
        static::assertSame(Message::SEVERITY_MEDIUM, $messages[0]->getSeverity());
        static::assertSame('The parameter "use" should be added.', $messages[0]->getMessage());
    }

    #[Test]
    public function keyWithValidUseShouldHaveNoMessages(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'use' => 'sig',
        ]);

        $bag = new MessageBag();
        $this->analyzer->analyze($jwk, $bag);

        static::assertEmpty($bag->all());
    }

    #[Test]
    public function keyWithInvalidUseShouldGetHighMessage(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'use' => 'invalid',
        ]);

        $bag = new MessageBag();
        $this->analyzer->analyze($jwk, $bag);

        $messages = $bag->all();
        static::assertCount(1, $messages);
        static::assertSame(Message::SEVERITY_HIGH, $messages[0]->getSeverity());
        static::assertStringContainsString('unsupported value "invalid"', $messages[0]->getMessage());
    }

    #[Test]
    public function keyWithValidKeyOpsArrayShouldHaveNoMessages(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'use' => 'sig',
            'key_ops' => ['sign', 'verify'],
        ]);

        $bag = new MessageBag();
        $this->analyzer->analyze($jwk, $bag);

        static::assertEmpty($bag->all());
    }

    #[Test]
    public function keyWithKeyOpsAsStringShouldGetHighMessage(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'use' => 'sig',
            'key_ops' => 'sign',
        ]);

        $bag = new MessageBag();
        $this->analyzer->analyze($jwk, $bag);

        $messages = $bag->all();
        static::assertCount(1, $messages);
        static::assertSame(Message::SEVERITY_HIGH, $messages[0]->getSeverity());
        static::assertSame(
            'The parameter "key_ops" must be an array of key operation values.',
            $messages[0]->getMessage()
        );
    }

    #[Test]
    public function keyWithInvalidKeyOpsValuesShouldGetHighMessage(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'use' => 'sig',
            'key_ops' => ['sign', 'invalid', 'unknownOp'],
        ]);

        $bag = new MessageBag();
        $this->analyzer->analyze($jwk, $bag);

        $messages = $bag->all();
        static::assertCount(1, $messages);
        static::assertSame(Message::SEVERITY_HIGH, $messages[0]->getSeverity());
        static::assertStringContainsString('unsupported values', $messages[0]->getMessage());
        static::assertStringContainsString('invalid', $messages[0]->getMessage());
        static::assertStringContainsString('unknownOp', $messages[0]->getMessage());
    }

    #[Test]
    public function keyWithAllValidKeyOpsValuesShouldHaveNoMessages(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'use' => 'enc',
            'key_ops' => ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'],
        ]);

        $bag = new MessageBag();
        $this->analyzer->analyze($jwk, $bag);

        static::assertEmpty($bag->all());
    }

    #[Test]
    public function keyWithEmptyKeyOpsArrayShouldHaveNoMessages(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
            'use' => 'sig',
            'key_ops' => [],
        ]);

        $bag = new MessageBag();
        $this->analyzer->analyze($jwk, $bag);

        static::assertEmpty($bag->all());
    }
}

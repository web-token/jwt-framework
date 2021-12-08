<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\MixedKeyTypes;
use Jose\Component\KeyManagement\Analyzer\MixedPublicAndPrivateKeys;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class JWKSetAnalyzerTest extends TestCase
{
    private ?KeysetAnalyzerManager $keysetAnalyzerManager = null;

    /**
     * @test
     */
    public function theKeysetHasNoKey(): void
    {
        $jwkset = new JWKSet([]);
        $messages = $this->getKeysetAnalyzer()
            ->analyze($jwkset)
        ;

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetDoesNotMixesKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK([
                'kty' => 'OKP',
            ]),
            new JWK([
                'kty' => 'OKP',
            ]),
            new JWK([
                'kty' => 'EC',
            ]),
            new JWK([
                'kty' => 'EC',
            ]),
        ]);
        $messages = $this->getKeysetAnalyzer()
            ->analyze($jwkset)
        ;

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetMixesKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK([
                'kty' => 'oct',
            ]),
            new JWK([
                'kty' => 'OKP',
            ]),
            new JWK([
                'kty' => 'OKP',
            ]),
            new JWK([
                'kty' => 'EC',
            ]),
            new JWK([
                'kty' => 'EC',
            ]),
        ]);
        $messages = $this->getKeysetAnalyzer()
            ->analyze($jwkset)
        ;

        static::assertNotEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetHasOnlyPrivateKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK([
                'kty' => 'OKP',
                'd' => 'foo',
            ]),
            new JWK([
                'kty' => 'RSA',
                'd' => 'foo',
            ]),
            new JWK([
                'kty' => 'EC',
                'd' => 'foo',
            ]),
        ]);
        $messages = $this->getKeysetAnalyzer()
            ->analyze($jwkset)
        ;

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetHasOnlyPublicKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK([
                'kty' => 'OKP',
            ]),
            new JWK([
                'kty' => 'RSA',
            ]),
            new JWK([
                'kty' => 'EC',
            ]),
        ]);
        $messages = $this->getKeysetAnalyzer()
            ->analyze($jwkset)
        ;

        static::assertEmpty($messages);
    }

    /**
     * @test
     */
    public function theKeysetMixesPublicAndPrivateKeys(): void
    {
        $jwkset = new JWKSet([
            new JWK([
                'kty' => 'OKP',
            ]),
            new JWK([
                'kty' => 'RSA',
            ]),
            new JWK([
                'kty' => 'EC',
                'd' => 'foo',
            ]),
        ]);
        $messages = $this->getKeysetAnalyzer()
            ->analyze($jwkset)
        ;

        static::assertNotEmpty($messages);
    }

    private function getKeysetAnalyzer(): KeysetAnalyzerManager
    {
        if ($this->keysetAnalyzerManager === null) {
            $this->keysetAnalyzerManager = new KeysetAnalyzerManager();
            $this->keysetAnalyzerManager->add(new MixedPublicAndPrivateKeys());
            $this->keysetAnalyzerManager->add(new MixedKeyTypes());
        }

        return $this->keysetAnalyzerManager;
    }
}

<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker;

use InvalidArgumentException;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Checker\NotBeforeChecker;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class ClaimCheckerManagerFactoryTest extends TestCase
{
    private ?ClaimCheckerManagerFactory $claimCheckerManagerFactory = null;

    /**
     * @test
     */
    public function theAliasListOfTheClaimCheckerManagerFactoryIsAvailable(): void
    {
        static::assertSame(['exp', 'iat', 'nbf', 'aud'], $this->getClaimCheckerManagerFactory()->aliases());
    }

    /**
     * @test
     */
    public function theAliasDoesNotExist(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The claim checker with the alias "foo" is not supported.');

        $this->getClaimCheckerManagerFactory()
            ->create(['foo'])
        ;
    }

    /**
     * @test
     */
    public function iCanCreateAClaimCheckerManager(): void
    {
        $manager = $this->getClaimCheckerManagerFactory()
            ->create(['exp', 'iat', 'nbf', 'aud'])
        ;
        static::assertCount(4, $manager->getCheckers());
    }

    /**
     * @test
     */
    public function iCanCheckValidPayloadClaims(): void
    {
        $payload = [
            'exp' => time() + 3600,
            'iat' => time() - 1000,
            'nbf' => time() - 100,
            'foo' => 'bar',
        ];
        $expected = $payload;
        unset($expected['foo']);
        $manager = $this->getClaimCheckerManagerFactory()
            ->create(['exp', 'iat', 'nbf', 'aud'])
        ;
        $result = $manager->check($payload);
        static::assertSame($expected, $result);
    }

    /**
     * @test
     */
    public function theMandatoryClaimsAreNotSet(): void
    {
        $this->expectException(MissingMandatoryClaimException::class);
        $this->expectExceptionMessage('The following claims are mandatory: bar.');

        $payload = [
            'exp' => time() + 3600,
            'iat' => time() - 1000,
            'nbf' => time() - 100,
            'foo' => 'bar',
        ];
        $expected = $payload;
        unset($expected['foo']);
        $manager = $this->getClaimCheckerManagerFactory()
            ->create(['exp', 'iat', 'nbf', 'aud'])
        ;
        $manager->check($payload, ['exp', 'foo', 'bar']);
    }

    private function getClaimCheckerManagerFactory(): ClaimCheckerManagerFactory
    {
        if ($this->claimCheckerManagerFactory === null) {
            $this->claimCheckerManagerFactory = new ClaimCheckerManagerFactory();
            $this->claimCheckerManagerFactory->add('exp', new ExpirationTimeChecker());
            $this->claimCheckerManagerFactory->add('iat', new IssuedAtChecker());
            $this->claimCheckerManagerFactory->add('nbf', new NotBeforeChecker());
            $this->claimCheckerManagerFactory->add('aud', new AudienceChecker('My Service'));
        }

        return $this->claimCheckerManagerFactory;
    }
}

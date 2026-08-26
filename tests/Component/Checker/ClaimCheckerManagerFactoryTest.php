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
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

/**
 * @internal
 */
final class ClaimCheckerManagerFactoryTest extends TestCase
{
    private ?ClaimCheckerManagerFactory $claimCheckerManagerFactory = null;

    #[Test]
    public function theAliasListOfTheClaimCheckerManagerFactoryIsAvailable(): void
    {
        static::assertSame(['exp', 'iat', 'nbf', 'aud'], $this->getClaimCheckerManagerFactory()->aliases());
    }

    #[Test]
    public function theAliasDoesNotExist(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The claim checker with the alias "foo" is not supported.');

        $this->getClaimCheckerManagerFactory()
            ->create(['foo']);
    }

    #[Test]
    public function iCanCreateAClaimCheckerManager(): void
    {
        $manager = $this->getClaimCheckerManagerFactory()
            ->create(['exp', 'iat', 'nbf', 'aud']);
        static::assertCount(4, $manager->getCheckers());
    }

    #[Test]
    public function iCanCheckValidPayloadClaims(): void
    {
        $clock = new MockClock();
        $now = $clock->now()
            ->getTimestamp();
        $payload = [
            'exp' => $now + 3600,
            'iat' => $now - 1000,
            'nbf' => $now - 100,
            'foo' => 'bar',
        ];
        $expected = $payload;
        unset($expected['foo']);
        $manager = $this->getClaimCheckerManagerFactory($clock)
            ->create(['exp', 'iat', 'nbf', 'aud']);
        $result = $manager->check($payload);
        static::assertSame($expected, $result);
    }

    #[Test]
    public function theMandatoryClaimsAreNotSet(): void
    {
        $this->expectException(MissingMandatoryClaimException::class);
        $this->expectExceptionMessage('The following claims are mandatory: bar.');

        $clock = new MockClock();
        $now = $clock->now()
            ->getTimestamp();
        $payload = [
            'exp' => $now + 3600,
            'iat' => $now - 1000,
            'nbf' => $now - 100,
            'foo' => 'bar',
        ];
        $expected = $payload;
        unset($expected['foo']);
        $manager = $this->getClaimCheckerManagerFactory($clock)
            ->create(['exp', 'iat', 'nbf', 'aud']);
        $manager->check($payload, ['exp', 'foo', 'bar']);
    }

    private function getClaimCheckerManagerFactory(ClockInterface $clock = new MockClock()): ClaimCheckerManagerFactory
    {
        if ($this->claimCheckerManagerFactory === null) {
            $this->claimCheckerManagerFactory = new ClaimCheckerManagerFactory();
            $this->claimCheckerManagerFactory->add('exp', new ExpirationTimeChecker(clock: $clock));
            $this->claimCheckerManagerFactory->add('iat', new IssuedAtChecker(clock: $clock));
            $this->claimCheckerManagerFactory->add('nbf', new NotBeforeChecker(clock: $clock));
            $this->claimCheckerManagerFactory->add('aud', new AudienceChecker('My Service'));
        }

        return $this->claimCheckerManagerFactory;
    }
}

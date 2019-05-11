<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimChecker
 * @group functional
 *
 * @internal
 * @coversNothing
 */
class ClaimCheckerManagerFactoryTest extends TestCase
{
    /**
     * @var null|ClaimCheckerManagerFactory
     */
    private $claimCheckerManagerFactory;

    /**
     * @test
     */
    public function theAliasListOfTheClaimCheckerManagerFactoryIsAvailable()
    {
        static::assertEquals(['exp', 'iat', 'nbf', 'aud'], $this->getClaimCheckerManagerFactory()->aliases());
    }

    /**
     * @test
     */
    public function theAliasDoesNotExist()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The claim checker with the alias "foo" is not supported.');

        $this->getClaimCheckerManagerFactory()->create(['foo']);
    }

    /**
     * @test
     */
    public function iCanCreateAClaimCheckerManager()
    {
        $manager = $this->getClaimCheckerManagerFactory()->create(['exp', 'iat', 'nbf', 'aud']);
        static::assertInstanceOf(ClaimCheckerManager::class, $manager);
    }

    /**
     * @test
     */
    public function iCanCheckValidPayloadClaims()
    {
        $payload = [
            'exp' => time() + 3600,
            'iat' => time() - 1000,
            'nbf' => time() - 100,
            'foo' => 'bar',
        ];
        $expected = $payload;
        unset($expected['foo']);
        $manager = $this->getClaimCheckerManagerFactory()->create(['exp', 'iat', 'nbf', 'aud']);
        $result = $manager->check($payload);
        static::assertEquals($expected, $result);
    }

    /**
     * @test
     */
    public function theMandatoryClaimsAreNotSet()
    {
        $this->expectException(\Jose\Component\Checker\MissingMandatoryClaimException::class);
        $this->expectExceptionMessage('The following claims are mandatory: bar.');

        $payload = [
            'exp' => time() + 3600,
            'iat' => time() - 1000,
            'nbf' => time() - 100,
            'foo' => 'bar',
        ];
        $expected = $payload;
        unset($expected['foo']);
        $manager = $this->getClaimCheckerManagerFactory()->create(['exp', 'iat', 'nbf', 'aud']);
        $manager->check($payload, ['exp', 'foo', 'bar']);
    }

    private function getClaimCheckerManagerFactory(): ClaimCheckerManagerFactory
    {
        if (null === $this->claimCheckerManagerFactory) {
            $this->claimCheckerManagerFactory = new ClaimCheckerManagerFactory();
            $this->claimCheckerManagerFactory->add('exp', new ExpirationTimeChecker());
            $this->claimCheckerManagerFactory->add('iat', new IssuedAtChecker());
            $this->claimCheckerManagerFactory->add('nbf', new NotBeforeChecker());
            $this->claimCheckerManagerFactory->add('aud', new AudienceChecker('My Service'));
        }

        return $this->claimCheckerManagerFactory;
    }
}

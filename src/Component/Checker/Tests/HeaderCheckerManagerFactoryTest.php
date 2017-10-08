<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Checker\Tests\Stub\Token;
use Jose\Component\Checker\Tests\Stub\TokenSupport;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimCheckerManager
 * @group Functional
 */
final class HeaderCheckerManagerFactoryTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header contains duplicated entries: alg.
     */
    public function testDuplicatedHeaderParameters()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['exp', 'iat', 'nbf', 'aud']);
        $payload = [];
        $protected = ['alg' => 'foo'];
        $unprotected = ['alg' => 'foo'];
        $token = Token::create(json_encode($payload), $protected, $unprotected);

        $headerCheckerManager->check($token, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage One or more headers are marked as critical, but they are missing or have not been checked: alg.
     */
    public function testTokenHasCriticalClaimsNotSatisfied()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['exp', 'iat', 'nbf', 'aud']);
        $payload = [];
        $protected = ['crit' => ['alg']];
        $unprotected = [];
        $token = Token::create(json_encode($payload), $protected, $unprotected);

        $headerCheckerManager->check($token, 0);
    }

    public function testTokenSuccessfullyCheckedWithCriticalHeaders()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['exp', 'iat', 'nbf', 'aud']);
        $payload = [];
        $protected = ['crit' => ['exp', 'iat'], 'exp' => time() + 3600, 'iat' => time() - 1000];
        $unprotected = [];
        $token = Token::create(json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
        self::assertTrue(true);
    }

    public function testTokenSuccessfullyCheckedWithUnsupportedClaims()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['exp', 'iat', 'nbf', 'aud']);
        $payload = [];
        $protected = ['foo' => 'bar'];
        $unprotected = [];
        $token = Token::create(json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
        self::assertTrue(true);
    }

    /**
     * @var HeaderCheckerManagerFactory|null
     */
    private $headerCheckerManagerFactory = null;

    /**
     * @return HeaderCheckerManagerFactory
     */
    private function getHeaderCheckerManagerFactory(): HeaderCheckerManagerFactory
    {
        if (null === $this->headerCheckerManagerFactory) {
            $this->headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
            $this->headerCheckerManagerFactory->add('exp', new ExpirationTimeChecker());
            $this->headerCheckerManagerFactory->add('iat', new IssuedAtChecker());
            $this->headerCheckerManagerFactory->add('nbf', new NotBeforeChecker());
            $this->headerCheckerManagerFactory->add('aud', new AudienceChecker('My Service'));

            $this->headerCheckerManagerFactory->addTokenTypeSupport(new TokenSupport());
        }

        return $this->headerCheckerManagerFactory;
    }
}

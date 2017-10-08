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
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
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
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage One or more headers are marked as critical, but they are missing or have not been checked: iss.
     */
    public function testTokenHasCriticalClaimsNotSatisfied()
    {
    }

    public function testTokenSuccessfullyCheckedWithCriticalHeaders()
    {
    }

    public function testTokenSuccessfullyCheckedWithUnsupportedClaims()
    {
    }

    /**
     * @var HeaderCheckerManager|null
     */
    private $headerCheckerManager = null;

    /**
     * @return HeaderCheckerManager
     */
    private function getHeaderCheckerManager(): HeaderCheckerManager
    {
        if (null === $this->headerCheckerManager) {
            $this->headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['exp', 'iat', 'nbf', 'aud', 'sub', 'iss', 'jti']);
        }

        return $this->headerCheckerManager;
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
        }

        return $this->headerCheckerManagerFactory;
    }
}

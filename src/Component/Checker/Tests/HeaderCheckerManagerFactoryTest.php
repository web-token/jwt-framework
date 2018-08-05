<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\Tests\Stub\IssuerChecker;
use Jose\Component\Checker\Tests\Stub\OtherToken;
use Jose\Component\Checker\Tests\Stub\Token;
use Jose\Component\Checker\Tests\Stub\TokenSupport;
use PHPUnit\Framework\TestCase;

/**
 * @group HeaderChecker
 * @group Functional
 */
class HeaderCheckerManagerFactoryTest extends TestCase
{
    /**
     * @test
     */
    public function theAliasListOfTheHeaderCheckerManagerFactoryIsAvailable()
    {
        static::assertEquals(['aud', 'iss'], $this->getHeaderCheckerManagerFactory()->aliases());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header contains duplicated entries: alg.
     */
    public function aHeaderMustNotContainDuplicatedHeaderParameters()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['alg' => 'foo'];
        $unprotected = ['alg' => 'foo'];
        $token = Token::create(\json_encode($payload), $protected, $unprotected);

        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidHeaderException
     * @expectedExceptionMessage One or more header parameters are marked as critical, but they are missing or have not been checked: alg.
     */
    public function theTokenHasCriticalHeaderNotSatisfied()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['crit' => ['alg']];
        $unprotected = [];
        $token = Token::create(\json_encode($payload), $protected, $unprotected);

        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     */
    public function theHeaderIsSuccessfullyChecked()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['crit' => ['aud'], 'aud' => 'My Service'];
        $unprotected = ['iss' => 'Another Service'];
        $token = Token::create(\json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
        static::assertTrue(true);
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidHeaderException
     * @expectedExceptionMessage The header parameter "crit" must be protected.
     */
    public function theCriticalHeaderParameterMustBeProtected()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['aud' => 'My Service'];
        $unprotected = ['crit' => ['aud']];
        $token = Token::create(\json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\InvalidHeaderException
     * @expectedExceptionMessage The header "crit" mus be a list of header parameters.
     */
    public function theCriticalHeaderParameterMustBeAListOfHeaderParameters()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['aud' => 'My Service', 'crit' => true];
        $unprotected = [];
        $token = Token::create(\json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     */
    public function theHeaderContainsUnknownParametersAndIsSuccessfullyChecked()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['foo' => 'bar', 'iss' => 'Another Service'];
        $unprotected = [];
        $token = Token::create(\json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
        static::assertTrue(true);
    }

    /**
     * @test
     * @expectedException \Jose\Component\Checker\MissingMandatoryHeaderParameterException
     * @expectedExceptionMessage The following header parameters are mandatory: mandatory.
     */
    public function theHeaderDoesNotContainSomeMandatoryParameters()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['aud' => 'Audience', 'iss' => 'Another Service'];
        $unprotected = ['foo' => 'bar'];
        $token = Token::create(\json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0, ['aud', 'iss', 'mandatory']);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported token type.
     */
    public function iTryToCheckATokenThatIsNotSupported()
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['foo' => 'bar'];
        $unprotected = [];
        $token = OtherToken::create(\json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
    }

    /**
     * @var HeaderCheckerManagerFactory|null
     */
    private $headerCheckerManagerFactory = null;

    private function getHeaderCheckerManagerFactory(): HeaderCheckerManagerFactory
    {
        if (null === $this->headerCheckerManagerFactory) {
            $this->headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
            $this->headerCheckerManagerFactory->add('aud', new AudienceChecker('My Service', true));
            $this->headerCheckerManagerFactory->add('iss', new IssuerChecker('Another Service'));
            $this->headerCheckerManagerFactory->addTokenTypeSupport(new TokenSupport());
        }

        return $this->headerCheckerManagerFactory;
    }
}

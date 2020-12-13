<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Checker;

use InvalidArgumentException;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Tests\Component\Checker\Stub\OtherToken;
use Jose\Tests\Component\Checker\Stub\Token;
use Jose\Tests\Component\Checker\Stub\TokenSupport;
use PHPUnit\Framework\TestCase;

/**
 * @group HeaderChecker
 * @group functional
 *
 * @internal
 */
class HeaderCheckerManagerFactoryTest extends TestCase
{
    /**
     * @var null|HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    /**
     * @test
     */
    public function theAliasListOfTheHeaderCheckerManagerFactoryIsAvailable(): void
    {
        static::assertEquals(['aud', 'iss'], $this->getHeaderCheckerManagerFactory()->aliases());
    }

    /**
     * @test
     */
    public function aHeaderMustNotContainDuplicatedHeaderParameters(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header contains duplicated entries: alg.');

        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['alg' => 'foo'];
        $unprotected = ['alg' => 'foo'];
        $token = new Token(json_encode($payload), $protected, $unprotected);

        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     */
    public function theTokenHasCriticalHeaderNotSatisfied(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('One or more header parameters are marked as critical, but they are missing or have not been checked: alg.');

        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['crit' => ['alg']];
        $unprotected = [];
        $token = new Token(json_encode($payload), $protected, $unprotected);

        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     */
    public function theHeaderIsSuccessfullyChecked(): void
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['crit' => ['aud'], 'aud' => 'My Service'];
        $unprotected = ['iss' => 'Another Service'];
        $token = new Token(json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     */
    public function theCriticalHeaderParameterMustBeProtected(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('The header parameter "crit" must be protected.');

        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['aud' => 'My Service'];
        $unprotected = ['crit' => ['aud']];
        $token = new Token(json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     */
    public function theCriticalHeaderParameterMustBeAListOfHeaderParameters(): void
    {
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage('The header "crit" must be a list of header parameters.');

        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['aud' => 'My Service', 'crit' => true];
        $unprotected = [];
        $token = new Token(json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     */
    public function theHeaderContainsUnknownParametersAndIsSuccessfullyChecked(): void
    {
        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['foo' => 'bar', 'iss' => 'Another Service'];
        $unprotected = [];
        $token = new Token(json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
    }

    /**
     * @test
     */
    public function theHeaderDoesNotContainSomeMandatoryParameters(): void
    {
        $this->expectException(MissingMandatoryHeaderParameterException::class);
        $this->expectExceptionMessage('The following header parameters are mandatory: mandatory.');

        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['aud' => 'Audience', 'iss' => 'Another Service'];
        $unprotected = ['foo' => 'bar'];
        $token = new Token(json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0, ['aud', 'iss', 'mandatory']);
    }

    /**
     * @test
     */
    public function iTryToCheckATokenThatIsNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported token type.');

        $headerCheckerManager = $this->getHeaderCheckerManagerFactory()->create(['aud', 'iss']);
        $payload = [];
        $protected = ['foo' => 'bar'];
        $unprotected = [];
        $token = new OtherToken(json_encode($payload), $protected, $unprotected);
        $headerCheckerManager->check($token, 0);
    }

    private function getHeaderCheckerManagerFactory(): HeaderCheckerManagerFactory
    {
        if (null === $this->headerCheckerManagerFactory) {
            $this->headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
            $this->headerCheckerManagerFactory->add('aud', new AudienceChecker('My Service', true));
            $this->headerCheckerManagerFactory->add('iss', new IssuerChecker(['Another Service']));
            $this->headerCheckerManagerFactory->addTokenTypeSupport(new TokenSupport());
        }

        return $this->headerCheckerManagerFactory;
    }
}

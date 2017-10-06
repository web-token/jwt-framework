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

namespace Jose\Test\Context;

use Behat\Behat\Context\Context;
use Behat\Symfony2Extension\Context\KernelDictionary;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;

/**
 * Class CompressionContext.
 */
final class CompressionContext implements Context
{
    use KernelDictionary;

    /**
     * @var null|CompressionMethodManager
     */
    private $compressionMethodsManager = null;

    /**
     * @Given the compression methods manager factory is available
     */
    public function theCompressionMethodsManagerFactoryIsAvailable()
    {
        if (false === $this->getContainer()->has(CompressionMethodManagerFactory::class)) {
            throw new \RuntimeException('The is no compression methods manager factory service.');
        }
    }

    /**
     * @When I create an compression methods manager with method DEF
     */
    public function iCreateAnCompressionMethodsManagerWithMethodDef()
    {
        /** @var CompressionMethodManagerFactory $factory */
        $factory = $this->getContainer()->get(CompressionMethodManagerFactory::class);
        $this->compressionMethodsManager = $factory->create(['DEF']);
    }

    /**
     * @Then I should get a compression manager with method DEF
     */
    public function iShouldGetACompressionManagerWithMethodDef()
    {
        if (!$this->compressionMethodsManager instanceof CompressionMethodManager) {
            throw new \RuntimeException();
        }
        if (['DEF'] !== $this->compressionMethodsManager->list()) {
            throw new \RuntimeException();
        }
    }
}

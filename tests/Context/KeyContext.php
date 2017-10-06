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

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\KeyManagement\X5UFactory;
use Behat\Behat\Context\Context;
use Behat\Symfony2Extension\Context\KernelDictionary;

/**
 * Class KeyContext.
 */
final class KeyContext implements Context
{
    use KernelDictionary;

    /**
     * @When I load a JKU keyset from Yahoo
     */
    public function iLoadAJkuKeysetFromYahoo()
    {
        /** @var JKUFactory $jkuFactory */
        $jkuFactory = $this->getContainer()->get(JKUFactory::class);

        $keyset = $jkuFactory->loadFromUrl('https://login.yahoo.com/openid/v1/certs');
        if (!$keyset instanceof JWKSet) {
            throw new \InvalidArgumentException('No key set received.');
        }
    }

    /**
     * @When I load a JKU keyset from Google
     */
    public function iLoadAJkuKeysetFromGoogle()
    {
        /** @var JKUFactory $jkuFactory */
        $jkuFactory = $this->getContainer()->get(JKUFactory::class);

        $keyset = $jkuFactory->loadFromUrl('https://www.googleapis.com/oauth2/v3/certs');
        if (!$keyset instanceof JWKSet) {
            throw new \InvalidArgumentException('No key set received.');
        }
    }

    /**
     * @When I load a X5U keyset from Google
     */
    public function iLoadAX5UKeysetFromGoogle()
    {
        /** @var X5UFactory $x5uFactory */
        $x5uFactory = $this->getContainer()->get(X5UFactory::class);

        $keyset = $x5uFactory->loadFromUrl('https://www.googleapis.com/oauth2/v1/certs');
        if (!$keyset instanceof JWKSet) {
            throw new \InvalidArgumentException('No key set received.');
        }
    }
}

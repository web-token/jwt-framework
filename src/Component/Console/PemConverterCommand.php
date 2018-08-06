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

namespace Jose\Component\Console;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\RSAKey;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class PemConverterCommand extends ObjectOutputCommand
{
    protected function configure()
    {
        parent::configure();
        $this
            ->setName('key:convert:pkcs1')
            ->setDescription('Converts a RSA or EC key into PKCS#1 key.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The key');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwk = $input->getArgument('jwk');
        $json = $this->jsonConverter->decode($jwk);
        if (!\is_array($json)) {
            throw new \InvalidArgumentException('Invalid key.');
        }
        $key = JWK::create($json);
        switch ($key->get('kty')) {
            case 'RSA':
                $pem = RSAKey::createFromJWK($key)->toPEM();

                break;
            case 'EC':
                $pem = ECKey::convertToPEM($key);

                break;
            default:
                throw new \InvalidArgumentException('Not a RSA or EC key.');
        }
        $this->prepareOutput($input, $output, $pem);
    }
}

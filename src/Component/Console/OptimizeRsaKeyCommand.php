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
use Jose\Component\KeyManagement\KeyConverter\RSAKey;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class OptimizeRsaKeyCommand extends ObjectOutputCommand
{
    protected function configure()
    {
        parent::configure();
        $this
            ->setName('key:optimize')
            ->setDescription('Optimize a RSA key by calculating additional primes (CRT).')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The RSA key.');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwk = $input->getArgument('jwk');
        $json = $this->jsonConverter->decode($jwk);
        if (!\is_array($json)) {
            throw new \InvalidArgumentException('Invalid input.');
        }
        $key = RSAKey::createFromJWK(JWK::create($json));
        $key->optimize();
        $this->prepareJsonOutput($input, $output, $key->toJwk());
    }
}

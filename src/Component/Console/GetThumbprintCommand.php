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

namespace Jose\Component\Console;

use Assert\Assertion;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class GetThumbprintCommand extends ObjectOutputCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:thumbprint')
            ->setDescription('Get the thumbprint of a JWK key.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The JWK key.')
            ->addOption('hash', null, InputOption::VALUE_OPTIONAL, 'The hashing algorithm.', 'sha256')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwk = $input->getArgument('jwk');
        $hash = $input->getOption('hash');
        Assertion::string($jwk, 'Invalid JWK');
        Assertion::string($hash, 'Invalid hash algorithm');
        $json = JsonConverter::decode($jwk);
        Assertion::isArray($json, 'Invalid input.');
        $key = JWK::create($json);
        $output->write($key->thumbprint($hash));
    }
}

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
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class GetThumbprintCommand extends ObjectOutputCommand
{
    protected function configure()
    {
        parent::configure();
        $this
            ->setName('key:thumbprint')
            ->setDescription('Get the thumbprint of a JWK key.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The JWK key.')
            ->addOption('hash', null, InputOption::VALUE_OPTIONAL, 'The hashing algorithm.', 'sha256');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwk = $input->getArgument('jwk');
        $hash = $input->getOption('hash');
        $json = $this->jsonConverter->decode($jwk);
        if (!\is_array($json)) {
            throw new \InvalidArgumentException('Invalid input.');
        }
        $key = JWK::create($json);
        $this->prepareOutput($input, $output, $key->thumbprint($hash));
    }
}

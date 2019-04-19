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
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class OctKeyGeneratorCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:generate:oct')
            ->setDescription('Generate an octet key (JWK format)')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $size = $input->getArgument('size');
        Assertion::integer($size, 'Invalid size');
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createOctKey($size, $args);
        $this->prepareJsonOutput($input, $output, $jwk);
    }
}

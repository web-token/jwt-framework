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

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_string;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class P12CertificateLoaderCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:load:p12')
            ->setDescription('Load a key from a P12 certificate file.')
            ->addArgument('file', InputArgument::REQUIRED, 'Filename of the P12 certificate.')
            ->addOption('secret', 's', InputOption::VALUE_OPTIONAL, 'Secret if the key is encrypted.', null)
        ;
    }

    /**
     * @throws InvalidArgumentException if the file is not valid
     * @throws InvalidArgumentException if the secret is not valid
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $file = $input->getArgument('file');
        $password = $input->getOption('secret');
        if (!is_string($file)) {
            throw new InvalidArgumentException('Invalid file');
        }
        if (!is_string($password)) {
            throw new InvalidArgumentException('Invalid secret');
        }
        $args = $this->getOptions($input);
        $jwk = JWKFactory::createFromPKCS12CertificateFile($file, $password, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return 0;
    }
}

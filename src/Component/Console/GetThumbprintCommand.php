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
use function is_array;
use function is_string;
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

    /**
     * @throws InvalidArgumentException if the JWK or the hashing function are invalid
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwk = $input->getArgument('jwk');
        if (!is_string($jwk)) {
            throw new InvalidArgumentException('Invalid JWK');
        }
        $hash = $input->getOption('hash');
        if (!is_string($hash)) {
            throw new InvalidArgumentException('Invalid hash algorithm');
        }
        $json = JsonConverter::decode($jwk);
        if (!is_array($json)) {
            throw new InvalidArgumentException('Invalid input.');
        }
        $key = new JWK($json);
        $output->write($key->thumbprint($hash));

        return 0;
    }
}

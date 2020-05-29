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
use Symfony\Component\Console\Output\OutputInterface;

final class EcKeyGeneratorCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:generate:ec')
            ->setDescription('Generate an EC key (JWK format)')
            ->addArgument('curve', InputArgument::REQUIRED, 'Curve of the key.')
        ;
    }

    /**
     * @throws InvalidArgumentException if the curve is invalid
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $curve = $input->getArgument('curve');
        if (!is_string($curve)) {
            throw new InvalidArgumentException('Invalid curve');
        }
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createECKey($curve, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return 0;
    }
}

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
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class RsaKeyGeneratorCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:generate:rsa')
            ->setDescription('Generate a RSA key (JWK format)')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.')
        ;
    }

    /**
     * @throws InvalidArgumentException if the key size is invalid
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $size = $input->getArgument('size');
        if (null === $size) {
            $size = 1;
        } elseif (is_array($size)) {
            $size = 1;
        } else {
            $size = (int) $size;
        }
        $args = $this->getOptions($input);
        if ($size < 1) {
            throw new InvalidArgumentException('Invalid size');
        }

        $jwk = JWKFactory::createRSAKey($size, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return 0;
    }
}

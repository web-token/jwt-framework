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

use InvalidArgumentException;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class RsaKeysetGeneratorCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('keyset:generate:rsa')
            ->setDescription('Generate a key set with RSA keys (JWK format)')
            ->addArgument('quantity', InputArgument::REQUIRED, 'Quantity of keys in the key set.')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $quantity = $input->getArgument('quantity');
        $size = $input->getArgument('size');
        if (!\is_int($quantity)) {
            throw new InvalidArgumentException('Invalid quantity');
        }
        if (!\is_int($size)) {
            throw new InvalidArgumentException('Invalid size');
        }

        $keyset = new JWKSet([]);
        for ($i = 0; $i < $quantity; ++$i) {
            $args = $this->getOptions($input);
            $keyset = $keyset->with(JWKFactory::createRSAKey($size, $args));
        }
        $this->prepareJsonOutput($input, $output, $keyset);
    }
}

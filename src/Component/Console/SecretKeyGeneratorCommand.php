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
use function is_bool;
use function is_string;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class SecretKeyGeneratorCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:generate:from_secret')
            ->setDescription('Generate an octet key (JWK format) using an existing secret')
            ->addArgument('secret', InputArgument::REQUIRED, 'The secret')
            ->addOption('is_b64', 'b', InputOption::VALUE_NONE, 'Indicates if the secret is Base64 encoded (useful for binary secrets)')
        ;
    }

    /**
     * @throws InvalidArgumentException if the secret is invalid
     * @throws InvalidArgumentException if the option "is_b4" is not a boolean
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $secret = $input->getArgument('secret');
        if (!is_string($secret)) {
            throw new InvalidArgumentException('Invalid secret');
        }
        $isBsae64Encoded = $input->getOption('is_b64');
        if (!is_bool($isBsae64Encoded)) {
            throw new InvalidArgumentException('Invalid option value for "is_b64"');
        }
        if ($isBsae64Encoded) {
            $secret = base64_decode($secret, true);
        }
        if (!is_string($secret)) {
            throw new InvalidArgumentException('Invalid secret');
        }
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createFromSecret($secret, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return 0;
    }
}

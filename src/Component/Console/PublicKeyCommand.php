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
use Symfony\Component\Console\Output\OutputInterface;

final class PublicKeyCommand extends ObjectOutputCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:convert:public')
            ->setDescription('Convert a private key into public key. Symmetric keys (shared keys) are not changed.')
            ->setHelp('This command converts a private key into a public key.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The JWK object')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwk = $this->getKey($input);
        $jwk = $jwk->toPublic();

        $this->prepareJsonOutput($input, $output, $jwk);

        return 0;
    }

    /**
     * @throws InvalidArgumentException if the key is invalid
     */
    private function getKey(InputInterface $input): JWK
    {
        $jwk = $input->getArgument('jwk');
        if (!is_string($jwk)) {
            throw new InvalidArgumentException('Invalid JWK');
        }
        $json = JsonConverter::decode($jwk);
        if (!is_array($json)) {
            throw new InvalidArgumentException('Invalid JWK');
        }

        return new JWK($json);
    }
}

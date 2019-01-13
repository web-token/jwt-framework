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

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class PublicKeyCommand extends ObjectOutputCommand
{
    protected function configure()
    {
        parent::configure();
        $this
            ->setName('key:convert:public')
            ->setDescription('Convert a private key into public key. Symmetric keys (shared keys) are not changed.')
            ->setHelp('This command converts a private key into a public key.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The JWK object');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwk = $this->getKey($input);
        $jwk = $jwk->toPublic();

        $this->prepareJsonOutput($input, $output, $jwk);
    }

    private function getKey(InputInterface $input): JWK
    {
        $jwk = $input->getArgument('jwk');
        $json = JsonConverter::decode($jwk);
        if (\is_array($json)) {
            return JWK::create($json);
        }

        throw new \InvalidArgumentException('The argument must be a valid JWK.');
    }
}

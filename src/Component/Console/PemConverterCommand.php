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
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\RSAKey;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class PemConverterCommand extends ObjectOutputCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('key:convert:pkcs1')
            ->setDescription('Converts a RSA or EC key into PKCS#1 key.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The key')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwk = $input->getArgument('jwk');
        if (!\is_string($jwk)) {
            throw new InvalidArgumentException('Invalid JWK');
        }
        $json = JsonConverter::decode($jwk);
        if (!\is_array($json)) {
            throw new InvalidArgumentException('Invalid key.');
        }
        $key = new JWK($json);
        switch ($key->get('kty')) {
            case 'RSA':
                $pem = RSAKey::createFromJWK($key)->toPEM();

                break;
            case 'EC':
                $pem = ECKey::convertToPEM($key);

                break;
            default:
                throw new InvalidArgumentException('Not a RSA or EC key.');
        }
        $output->write($pem);
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_array;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class RsaKeyGeneratorCommand extends GeneratorCommand
{
    protected static $defaultName = 'key:generate:rsa';

    protected function configure(): void
    {
        parent::configure();
        $this->setDescription('Generate a RSA key (JWK format)')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $size = $input->getArgument('size');
        if ($size === null) {
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

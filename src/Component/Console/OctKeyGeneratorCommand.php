<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class OctKeyGeneratorCommand extends GeneratorCommand
{
    protected static $defaultName = 'key:generate:oct';

    protected function configure(): void
    {
        parent::configure();
        $this->setDescription('Generate an octet key (JWK format)')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $size = (int) $input->getArgument('size');
        if ($size < 1) {
            throw new InvalidArgumentException('Invalid size');
        }
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createOctKey($size, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return 0;
    }
}

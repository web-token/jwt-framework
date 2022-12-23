<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_string;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class P12CertificateLoaderCommand extends GeneratorCommand
{
    protected static $defaultName = 'key:load:p12';

    protected static $defaultDescription = 'Load a key from a P12 certificate file.';

    protected function configure(): void
    {
        parent::configure();
        $this->addArgument('file', InputArgument::REQUIRED, 'Filename of the P12 certificate.')
            ->addOption('secret', 's', InputOption::VALUE_OPTIONAL, 'Secret if the key is encrypted.', null);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $file = $input->getArgument('file');
        $password = $input->getOption('secret');
        if (! is_string($file)) {
            throw new InvalidArgumentException('Invalid file');
        }
        if (! is_string($password)) {
            throw new InvalidArgumentException('Invalid secret');
        }
        $args = $this->getOptions($input);
        $jwk = JWKFactory::createFromPKCS12CertificateFile($file, $password, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return self::SUCCESS;
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_string;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class X509CertificateLoaderCommand extends GeneratorCommand
{
    protected static $defaultName = 'key:load:x509';

    protected static $defaultDescription = 'Load a key from a X.509 certificate file.';

    protected function configure(): void
    {
        parent::configure();
        $this->addArgument('file', InputArgument::REQUIRED, 'Filename of the X.509 certificate.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $file = $input->getArgument('file');
        if (! is_string($file)) {
            throw new InvalidArgumentException('Invalid file');
        }
        $args = [];
        foreach (['use', 'alg'] as $key) {
            $value = $input->getOption($key);
            if ($value !== null) {
                $args[$key] = $value;
            }
        }

        $jwk = JWKFactory::createFromCertificateFile($file, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return self::SUCCESS;
    }
}

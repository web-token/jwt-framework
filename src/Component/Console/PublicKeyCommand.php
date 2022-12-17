<?php

declare(strict_types=1);

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
    protected static $defaultName = 'key:convert:public';

    protected static $defaultDescription = 'Convert a private key into public key. Symmetric keys (shared keys) are not changed.';

    protected function configure(): void
    {
        parent::configure();
        $this->setHelp('This command converts a private key into a public key.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The JWK object');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwk = $this->getKey($input);
        $jwk = $jwk->toPublic();

        $this->prepareJsonOutput($input, $output, $jwk);

        return self::SUCCESS;
    }

    private function getKey(InputInterface $input): JWK
    {
        $jwk = $input->getArgument('jwk');
        if (! is_string($jwk)) {
            throw new InvalidArgumentException('Invalid JWK');
        }
        $json = JsonConverter::decode($jwk);
        if (! is_array($json)) {
            throw new InvalidArgumentException('Invalid JWK');
        }

        return new JWK($json);
    }
}

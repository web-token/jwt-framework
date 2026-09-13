<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JwkThumbprintUri;
use Jose\Component\Core\Util\JsonConverter;
use Override;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use function in_array;
use function is_array;
use function is_string;

/**
 * Prints the RFC 7638 thumbprint of a key, or its RFC 9278 thumbprint URI with the "--uri" option.
 *
 * The "--hash" option takes the name PHP gives to the function ("sha256"). With "--uri", the IANA name carried by the
 * URI ("sha-256") is accepted too, and the PHP names of the supported functions are translated, so that the same
 * "--hash sha256" works in both modes.
 */
#[AsCommand(name: 'key:thumbprint', description: 'Get the thumbprint of a JWK key.')]
final class GetThumbprintCommand extends ObjectOutputCommand
{
    #[Override]
    protected function configure(): void
    {
        parent::configure();
        $this->addArgument('jwk', InputArgument::REQUIRED, 'The JWK key.')
            ->addOption('hash', null, InputOption::VALUE_OPTIONAL, 'The hashing algorithm.', 'sha256')
            ->addOption(
                'uri',
                null,
                InputOption::VALUE_NONE,
                'Output the JWK Thumbprint URI instead of the bare thumbprint. The hashing algorithm may then be given by its IANA name (e.g. "sha-256").'
            );
    }

    #[Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwk = $input->getArgument('jwk');
        if (! is_string($jwk)) {
            throw new InvalidKeyException('Invalid JWK');
        }
        $hash = $input->getOption('hash');
        if (! is_string($hash)) {
            throw new InvalidArgumentException('Invalid hash algorithm');
        }
        $json = JsonConverter::decode($jwk);
        if (! is_array($json)) {
            throw new InvalidArgumentException('Invalid input.');
        }
        $key = new JWK($json);
        if ($input->getOption('uri') === true) {
            $output->write($key->thumbprintUri(self::ianaHashAlgorithm($hash)));

            return self::SUCCESS;
        }
        $output->write($key->thumbprint($hash));

        return self::SUCCESS;
    }

    /**
     * Translates the PHP name of a hash function into the IANA name when the two differ ("sha256" to "sha-256"). A
     * name that is not a PHP alias of a supported function is returned as is, and JwkThumbprintUri decides.
     */
    private static function ianaHashAlgorithm(string $hash): string
    {
        $candidate = preg_replace('/^sha(\d{3})$/', 'sha-$1', $hash) ?? $hash;

        return in_array($candidate, JwkThumbprintUri::hashAlgorithms(), true) ? $candidate : $hash;
    }
}

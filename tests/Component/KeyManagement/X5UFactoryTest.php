<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\X5UFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use function file_get_contents;
use function json_encode;
use function str_replace;
use function trim;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class X5UFactoryTest extends TestCase
{
    private const CERTIFICATE = __DIR__ . '/RSA/PEM/2048b-rsa-example-cert.pem';

    private const THUMBPRINT = 'B4plbjZwSZyZG7AnRoIFive9wF_EYsYF8PiVgXmBbNc';

    #[Test]
    #[DataProvider('entriesThatNameALocalFile')]
    public function anEntryCannotNameALocalFile(string $entry): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to load the certificate.');

        $this->loadEntry($entry);
    }

    #[Test]
    #[DataProvider('certificateEntries')]
    public function theCertificateOfAnEntryIsLoaded(string $entry): void
    {
        static::assertSame(self::THUMBPRINT, $this->loadEntry($entry)->get('x5t#256'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function entriesThatNameALocalFile(): iterable
    {
        yield 'file URL' => ['file://' . self::CERTIFICATE];
        yield 'file URL through a directory named after the marker' => [
            'file:///-----BEGIN CERTIFICATE-----/..' . self::CERTIFICATE,
        ];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function certificateEntries(): iterable
    {
        $pem = (string) file_get_contents(self::CERTIFICATE);

        yield 'base64 body' => [
            trim(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $pem)),
        ];
        yield 'PEM block' => [$pem];
        yield 'PEM block preceded by text' => ["Subject: www.example.com\n" . $pem];
    }

    private function loadEntry(string $entry): JWK
    {
        $client = new MockHttpClient(new MockResponse(json_encode([
            'partner' => $entry,
        ], JSON_THROW_ON_ERROR)));

        return (new X5UFactory($client))
            ->loadFromUrl('https://partner.example.com/x5u')
            ->get('partner');
    }
}

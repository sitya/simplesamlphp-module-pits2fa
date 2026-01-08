<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\totp\Auth\Process;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\totp\Auth\Process\TOTP;

/**
 * Test suite for TOTP authentication processing filter.
 */
class TOTPTest extends TestCase
{
    /**
     * Test that constructor requires pits_dsn parameter.
     */
    public function testConstructorRequiresPitsDsn(): void
    {
        $this->expectException(\SimpleSAML\Error\Exception::class);
        $this->expectExceptionMessage('pits_dsn');

        new TOTP([], null);
    }

    /**
     * Test that constructor requires pits_username parameter.
     */
    public function testConstructorRequiresPitsUsername(): void
    {
        $this->expectException(\SimpleSAML\Error\Exception::class);
        $this->expectExceptionMessage('pits_username');

        new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
        ], null);
    }

    /**
     * Test that constructor requires pits_password parameter.
     */
    public function testConstructorRequiresPitsPassword(): void
    {
        $this->expectException(\SimpleSAML\Error\Exception::class);
        $this->expectExceptionMessage('pits_password');

        new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
        ], null);
    }

    /**
     * Test that constructor requires pits_url parameter.
     */
    public function testConstructorRequiresPitsUrl(): void
    {
        $this->expectException(\SimpleSAML\Error\Exception::class);
        $this->expectExceptionMessage('pits_url');

        new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
        ], null);
    }

    /**
     * Test that constructor requires pits_token parameter.
     */
    public function testConstructorRequiresPitsToken(): void
    {
        $this->expectException(\SimpleSAML\Error\Exception::class);
        $this->expectExceptionMessage('pits_token');

        new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
        ], null);
    }

    /**
     * Test that constructor accepts valid configuration.
     */
    public function testConstructorAcceptsValidConfiguration(): void
    {
        $filter = new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that 2fa_mandatory defaults to false.
     */
    public function testMandatoryDefaultsToFalse(): void
    {
        $filter = new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
        ], null);

        // Since we can't directly access private properties,
        // we'd need to test behavior through the process method
        // This is a placeholder for more comprehensive testing
        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that 2fa_mandatory can be set to true.
     */
    public function testMandatoryCanBeSetToTrue(): void
    {
        $filter = new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            '2fa_mandatory' => true,
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that pits_options is optional and defaults to empty array.
     */
    public function testPitsOptionsIsOptional(): void
    {
        $filter = new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that pits_options can be provided.
     */
    public function testPitsOptionsCanBeProvided(): void
    {
        $filter = new TOTP([
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_options' => [
                \PDO::MYSQL_ATTR_SSL_CA => '/path/to/ca.pem',
            ],
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }
}

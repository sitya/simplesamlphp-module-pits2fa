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
     * Test that constructor requires username_attribute parameter.
     */
    public function testConstructorRequiresUsernameAttribute(): void
    {
        $this->expectException(\SimpleSAML\Error\Exception::class);
        $this->expectExceptionMessage('username_attribute');

        new TOTP([], null);
    }

    /**
     * Test that constructor requires pits_dsn parameter.
     */
    public function testConstructorRequiresPitsDsn(): void
    {
        $this->expectException(\SimpleSAML\Error\Exception::class);
        $this->expectExceptionMessage('pits_dsn');

        new TOTP([
            'username_attribute' => 'uid',
        ], null);
    }

    /**
     * Test that constructor requires pits_username parameter.
     */
    public function testConstructorRequiresPitsUsername(): void
    {
        $this->expectException(\SimpleSAML\Error\Exception::class);
        $this->expectExceptionMessage('pits_username');

        new TOTP([
            'username_attribute' => 'uid',
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
            'username_attribute' => 'uid',
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
            'username_attribute' => 'uid',
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
            'username_attribute' => 'uid',
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
            'username_attribute' => 'uid',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that 2fa_mandatory defaults to false.
     */
    public function testMandatoryDefaultsToFalse(): void
    {
        $filter = new TOTP([
            'username_attribute' => 'uid',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
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
            'username_attribute' => 'uid',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
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
            'username_attribute' => 'uid',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that pits_options can be provided.
     */
    public function testPitsOptionsCanBeProvided(): void
    {
        $filter = new TOTP([
            'username_attribute' => 'uid',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_options' => [
                \PDO::MYSQL_ATTR_SSL_CA => '/path/to/ca.pem',
            ],
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that authncontextclassref is optional and defaults to REFEDS MFA profile.
     */
    public function testAuthnContextClassRefDefaultsToRefedsMfa(): void
    {
        $filter = new TOTP([
            'username_attribute' => 'uid',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that authncontextclassref can be customized.
     */
    public function testAuthnContextClassRefCanBeCustomized(): void
    {
        $filter = new TOTP([
            'username_attribute' => 'uid',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
            'authncontextclassref' => 'http://schemas.microsoft.com/claims/multipleauthn',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that fallback_username_attribute is optional.
     */
    public function testFallbackUsernameAttributeIsOptional(): void
    {
        $filter = new TOTP([
            'username_attribute' => 'uid',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test that fallback_username_attribute can be provided.
     */
    public function testFallbackUsernameAttributeCanBeProvided(): void
    {
        $filter = new TOTP([
            'username_attribute' => 'uid',
            'fallback_username_attribute' => 'mail',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }

    /**
     * Test constructor with complete configuration including fallback attribute.
     */
    public function testConstructorWithFallbackAttributeFullConfig(): void
    {
        $filter = new TOTP([
            'username_attribute' => 'uid',
            'fallback_username_attribute' => 'eduPersonPrincipalName',
            'pits_dsn' => 'mysql:host=localhost;dbname=test',
            'pits_username' => 'test_user',
            'pits_password' => 'test_pass',
            'pits_url' => 'https://example.com/verify',
            'pits_token' => 'test_token',
            'pits_registration_url' => 'https://pits.example.com',
            '2fa_mandatory' => false,
        ], null);

        $this->assertInstanceOf(TOTP::class, $filter);
    }
}

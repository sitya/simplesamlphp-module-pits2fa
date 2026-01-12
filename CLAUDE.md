# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

SimpleSAMLphp authentication processing filter (authproc) implementing TOTP-based second-factor authentication using an external PITS (authentication service). The module runs after successful username/password authentication and integrates with PITS via database queries and HTTP API calls.

## Build & Test Commands

### Docker-based (Recommended)
```bash
./docker-run.sh setup          # First-time setup
./docker-run.sh test           # Run all tests
./docker-run.sh test-verbose   # Run tests with detailed output
./docker-run.sh exec <cmd>     # Execute command in container
```

### Local PHP
```bash
composer install                                    # Install dependencies
composer test                                       # Run all tests
vendor/bin/phpunit                                  # Run PHPUnit directly
vendor/bin/phpunit --filter TestName                # Run specific test
vendor/bin/phpunit --testsuite "Unit Tests"         # Run unit tests only
vendor/bin/phpunit --testsuite "Integration Tests"  # Run integration tests only
vendor/bin/php-cs-fixer fix                         # Format code
```

### Integration Test Infrastructure
```bash
docker-compose -f docker-compose.test.yml up -d    # Start test services (MySQL + mock PITS API)
docker-compose -f docker-compose.test.yml down     # Stop test services
```

## Architecture

### Core Components

1. **TOTP.php** (`src/Auth/Process/TOTP.php`)
   - Main authproc filter extending `SimpleSAML\Auth\ProcessingFilter`
   - Queries PITS database to check TOTP registration status
   - Verifies TOTP codes via PITS HTTP API
   - Manages authentication state and retry attempts (max 3)

2. **Verify.php** (`src/Controller/Verify.php`)
   - HTTP controller for TOTP code submission form
   - Routes defined in `config/routes.yaml`
   - Delegates to `TOTP::handleVerification()`

3. **ErrorCodes.php** (`src/Error/ErrorCodes.php`)
   - Custom error codes for TOTP module
   - Provides user-facing error messages

4. **Templates** (`templates/`)
   - `verify.twig` - TOTP input form
   - `register_required.twig` - Registration required error
   - `max_attempts.twig` - Max attempts exceeded error

### Authentication Flow

1. User completes username/password authentication
2. **Username extraction:**
   - First tries primary `username_attribute` from state attributes
   - If missing/empty, tries optional `fallback_username_attribute`
   - **If both missing:**
     - `2fa_mandatory=true` → Throw exception (authentication fails)
     - `2fa_mandatory=false` → Log warning and continue without 2FA
3. TOTP filter calls database stored procedure: `CALL eduid_2fa_required(:username)`
   - Returns `0` (no TOTP) or `1` (has TOTP)
4. **If no TOTP registered:**
   - `2fa_mandatory=false` → Continue without TOTP
   - `2fa_mandatory=true` → Show registration required error
5. **If TOTP registered:**
   - Show verification form (`verify.twig`)
   - User submits 6-digit code
   - POST to PITS API: `{token, username, code, service: "eduid"}`
   - API returns `{"result": "OK"}` or `{"result": "FAIL"}`
   - Max 3 attempts, then authentication fails

### State Management

Uses SimpleSAMLphp's state mechanism to persist:
- `$state['totp:username']` - Current user
- `$state['totp:attempts']` - Verification attempt counter
- `$state['totp:error']` - Error flag for display
- `$state['totp:config']` - Filter configuration

### Database Integration

**Connection:** PDO with SSL verification enabled
**Stored Procedure:** `eduid_2fa_required(:username)` returns integer (0 or 1)
**Security:** Uses prepared statements to prevent SQL injection

### API Integration

**Endpoint:** POST to configured `pits_url`
**Parameters:** `token`, `username`, `code`, `service=eduid`
**Response:** JSON with `{"result": "OK"|"FAIL"}`
**Security:** TLS certificate validation enforced

## Configuration

Module is configured in SimpleSAMLphp's `config/authproc.php`:

```php
'authproc' => [
    100 => [
        'class' => 'totp:TOTP',
        '2fa_mandatory' => false,                    // Enforce TOTP for all users
        'username_attribute' => 'uid',               // Attribute containing username
        'fallback_username_attribute' => 'mail',     // Optional: fallback if primary attribute missing
        'pits_dsn' => 'mysql:host=...;dbname=...',  // Database DSN
        'pits_username' => 'db_user',                // Database username
        'pits_password' => 'db_pass',                // Database password
        'pits_options' => [],                        // PDO options
        'pits_url' => 'https://pits.example.com/api/verify',
        'pits_token' => 'api_token',
        'pits_registration_url' => 'https://pits.example.com/register',
    ],
],
```

## Code Style

- PSR-12 coding standards
- Strict types: `declare(strict_types=1);` at file top
- Type hints for all parameters and return values
- Never log TOTP codes, tokens, or passwords
- Use SimpleSAMLphp's `SimpleSAML\Error\*` exceptions for error handling
- Use SimpleSAMLphp's `SimpleSAML\Logger` for logging (INFO, DEBUG, WARNING, ERROR levels)

## Security Constraints

1. **Never log sensitive data:** TOTP codes, API tokens, passwords
2. **TLS enforcement:** Database SSL verification, HTTPS API calls with cert validation
3. **Session-based retry limiting:** Max 3 attempts stored in state
4. **Input validation:** Client-side HTML5 pattern + server-side trimming
5. **No SQL injection:** PDO prepared statements only

## Error Handling

Uses SimpleSAMLphp error system:
- `SimpleSAML\Error\Exception` - Configuration errors
- `SimpleSAML\Error\Error` - Runtime errors with custom codes:
  - `DBERROR` - Database connection/query failure
  - `DBQUERYERROR` - Unexpected database result
  - `NETWORKERROR` - API connection failure
  - `INVALIDRESPONSE` - Invalid API response
  - `NOTOTPREGISTERED` - Must register TOTP (mandatory mode)
  - `TOTPFAILED` - Max verification attempts exceeded

## Test Structure

- **Unit tests:** `tests/Auth/Process/TOTPTest.php` - Configuration validation, constructor behavior
- **Integration tests:** `tests/Integration/TOTPIntegrationTest.php` - Database queries, API calls, complete flows
- **Test infrastructure:** Docker Compose with MySQL + mock PITS API
- **Test data:** See `tests/docker/sql/init.sql` for test users

## Important Files

- `src/Auth/Process/TOTP.php` - Main authentication logic (~400 lines)
- `src/Controller/Verify.php` - HTTP form handler
- `src/Error/ErrorCodes.php` - Custom error definitions
- `templates/*.twig` - User-facing HTML templates
- `config/routes.yaml` - HTTP route definitions
- `phpunit.xml` - Test configuration
- `composer.json` - Dependencies and autoloading

## Development Notes

- Username extraction assumes standard SAML attributes (configurable via `username_attribute`)
- Retry counter and state are session-scoped via SimpleSAMLphp's state mechanism
- Module integrates into SimpleSAMLphp's authproc chain - runs after primary authentication succeeds
- For comprehensive testing, use Docker infrastructure (MySQL + mock API) with `./docker-run.sh`
- SimpleSAMLphp must be installed as a dependency for the module to work

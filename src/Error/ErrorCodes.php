<?php

declare(strict_types=1);

namespace SimpleSAML\Module\totp\Error;

use SimpleSAML\Error\ErrorCodes as BaseErrorCodes;
use SimpleSAML\Locale\Translate;

/**
 * Custom error codes for the TOTP module.
 */
class ErrorCodes extends BaseErrorCodes
{
    final public const NOTOTPREGISTERED = 'NOTOTPREGISTERED';
    final public const DBQUERYERROR = 'DBQUERYERROR';
    final public const DBERROR = 'DBERROR';
    final public const NETWORKERROR = 'NETWORKERROR';
    final public const INVALIDRESPONSE = 'INVALIDRESPONSE';
    final public const TOTPFAILED = 'TOTPFAILED';

    /**
     * @inheritDoc
     */
    public function getCustomTitles(): array
    {
        return [
            self::NOTOTPREGISTERED => Translate::noop('TOTP not registered'),
            self::DBQUERYERROR => Translate::noop('Database query error'),
            self::DBERROR => Translate::noop('Database error'),
            self::NETWORKERROR => Translate::noop('Network error'),
            self::INVALIDRESPONSE => Translate::noop('Invalid response'),
            self::TOTPFAILED => Translate::noop('TOTP verification failed'),
        ];
    }

    /**
     * @inheritDoc
     */
    public function getCustomDescriptions(): array
    {
        return [
            self::NOTOTPREGISTERED => Translate::noop(
                'You do not have TOTP (two-factor authentication) registered. ' .
                'Please register TOTP at https://pits.example.com before attempting to log in.'
            ),
            self::DBQUERYERROR => Translate::noop(
                'A database query returned an unexpected result. ' .
                'Please contact your system administrator if this problem persists.'
            ),
            self::DBERROR => Translate::noop(
                'Failed to connect to the authentication database or execute a database query. ' .
                'Please try again later. If the problem persists, contact your system administrator.'
            ),
            self::NETWORKERROR => Translate::noop(
                'Failed to connect to the TOTP verification service. ' .
                'Please try again later. If the problem persists, contact your system administrator.'
            ),
            self::INVALIDRESPONSE => Translate::noop(
                'The TOTP verification service returned an invalid response. ' .
                'Please contact your system administrator.'
            ),
            self::TOTPFAILED => Translate::noop(
                'TOTP verification failed after the maximum number of attempts. ' .
                'Please try logging in again.'
            ),
        ];
    }
}

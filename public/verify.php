<?php

declare(strict_types=1);

/**
 * TOTP verification endpoint.
 *
 * This script handles the TOTP verification form submission.
 */

if (!isset($_REQUEST['StateId'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing required StateId query parameter.');
}

$stateId = $_REQUEST['StateId'];

\SimpleSAML\Module\totp\Auth\Process\TOTP::handleVerification($stateId);

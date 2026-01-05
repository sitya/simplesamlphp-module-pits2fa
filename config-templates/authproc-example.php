<?php

declare(strict_types=1);

/**
 * Example authproc configuration snippet.
 *
 * Add this to your SimpleSAMLphp config/authsources.php or config/config.php
 * in the appropriate authproc section.
 *
 * For metadata-based IdP configuration, add to config/saml20-idp-hosted.php:
 *
 * $metadata['https://your-idp.example.com'] = [
 *     // ... other config ...
 *     'authproc' => [
 *         // ... other filters ...
 *         100 => [
 *             'class' => 'totp:TOTP',
 *             '2fa_mandatory' => false,
 *             'pits_dsn' => 'mysql:host=pits-db.example.com;dbname=pits;charset=utf8mb4',
 *             'pits_url' => 'https://pits.example.com/api/verify',
 *             'pits_token' => 'your_secure_token_here',
 *         ],
 *     ],
 * ];
 */

$authproc = [
    // Core filters (do not remove these)
    10 => [
        'class' => 'core:AttributeMap',
        'name2oid',
    ],
    
    // Add TOTP 2FA filter
    // Priority 100 ensures it runs after primary authentication
    100 => [
        'class' => 'totp:TOTP',
        
        // Whether TOTP is mandatory
        '2fa_mandatory' => false,
        
        // PITS database connection
        'pits_dsn' => 'mysql:host=pits-db.example.com;dbname=pits;charset=utf8mb4',
        
        // PITS verification service
        'pits_url' => 'https://pits.example.com/api/verify',
        
        // PITS API token
        'pits_token' => 'your_secure_token_here',
    ],
];

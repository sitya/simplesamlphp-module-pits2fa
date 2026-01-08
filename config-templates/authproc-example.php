<?php

declare(strict_types=1);

'authproc' = [
    // Add TOTP 2FA filter
    // Priority 100 ensures it runs after primary authentication
    100 => [
        'class' => 'totp:TOTP',
        // Whether TOTP is mandatory
        '2fa_mandatory' => false,
        // Attribute name to use for username (e.g., 'uid', 'eduPersonPrincipalName', 'mail')
        'username_attribute' => 'uid',
        // PITS database connection
        'pits_dsn' => 'mysql:host=pits-db.example.com;dbname=pits;charset=utf8mb4',
        'pits_username' => 'pits_user',
        'pits_password' => 'pits_password',
        // Optional PDO connection options (defaults provided if not set)
        'pits_options' => [
            // Example: Custom SSL CA certificate
            // PDO::MYSQL_ATTR_SSL_CA => '/path/to/ca-cert.pem',
            // PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true,
        ],
        // PITS verification service
        'pits_url' => 'https://pits.example.com/api/verify',
        // PITS API token
        'pits_token' => 'your_secure_token_here',
    ],
];

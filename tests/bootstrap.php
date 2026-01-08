<?php

declare(strict_types=1);

/**
 * PHPUnit bootstrap file.
 */

$autoloadFile = __DIR__ . '/../vendor/autoload.php';

if (!file_exists($autoloadFile)) {
    throw new RuntimeException(
        'Install dependencies using Composer before running tests: composer install'
    );
}

require_once $autoloadFile;

<?php
declare(strict_types=1);

// The directory's .htaccess is applied before PHP request initialization.
// This response is only observable when startup reaches the script.
require dirname(__DIR__) . '/health.php';

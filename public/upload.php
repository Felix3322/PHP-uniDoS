<?php
declare(strict_types=1);

// A normal endpoint. CVE-2026-109618's mod_php startup path can fail
// before this script executes; reaching this page is not a success marker.
header('Content-Type: application/json');
header('X-Lab-Worker-Pid: ' . getmypid());
echo json_encode([
    'pid' => getmypid(),
    'php' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'post_fields' => count($_POST),
    'files' => count($_FILES),
], JSON_UNESCAPED_SLASHES), "\n";

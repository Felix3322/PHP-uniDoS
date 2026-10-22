<?php
declare(strict_types=1);

// A normal endpoint. CVE-2026-109618's mod_php startup path can fail
// before this script executes; reaching this page is not a success marker.
header('Content-Type: application/json');
header('X-Lab-Worker-Pid: ' . getmypid());
echo json_encode([
    'lab' => 'official-cve-lab-v1',
    'pid' => getmypid(),
    'php' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'max_multipart_body_parts' => ini_get('max_multipart_body_parts'),
    'max_file_uploads' => ini_get('max_file_uploads'),
    'post_fields' => count($_POST),
    'files' => count($_FILES),
], JSON_UNESCAPED_SLASHES), "\n";

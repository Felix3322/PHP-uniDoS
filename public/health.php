<?php
declare(strict_types=1);

header('Content-Type: application/json');
header('X-Lab-Worker-Pid: ' . getmypid());
echo json_encode([
    'lab' => 'official-cve-lab-v1',
    'pid' => getmypid(),
    'php' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'fatal_error_backtraces' => ini_get('fatal_error_backtraces'),
    'auto_detect_line_endings' => ini_get('auto_detect_line_endings'),
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'max_multipart_body_parts' => ini_get('max_multipart_body_parts'),
    'max_file_uploads' => ini_get('max_file_uploads'),
    'upload_progress' => ini_get('session.upload_progress.enabled'),
], JSON_UNESCAPED_SLASHES), "\n";

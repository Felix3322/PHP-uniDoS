<?php
declare(strict_types=1);

header('Content-Type: application/json');
header('X-Lab-Worker-Pid: ' . getmypid());
if (!session_start()) {
    http_response_code(500);
    echo json_encode(['seeded' => false, 'pid' => getmypid()]), "\n";
    exit;
}
$_SESSION['lab_seed'] = 'ready';
$sessionPath = session_save_path();
session_write_close();
echo json_encode([
    'seeded' => true,
    'pid' => getmypid(),
    'session_name' => session_name(),
    'session_path' => $sessionPath ?: sys_get_temp_dir(),
    'upload_progress_enabled' => ini_get('session.upload_progress.enabled'),
    'upload_progress_cleanup' => ini_get('session.upload_progress.cleanup'),
    'use_only_cookies' => ini_get('session.use_only_cookies'),
    'use_strict_mode' => ini_get('session.use_strict_mode'),
], JSON_UNESCAPED_SLASHES), "\n";

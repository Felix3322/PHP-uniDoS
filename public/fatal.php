<?php
declare(strict_types=1);

// Candidate producer for the PHP 8.5 fatal-backtrace state path.
// The subsequent request must run in this same persistent worker.
error_log('CVE_LAB_FATAL_PRODUCER pid=' . getmypid());
header('X-Lab-Worker-Pid: ' . getmypid());
echo 'producer_pid=', getmypid(), "\n";
flush();
call_to_undefined_lab_function();

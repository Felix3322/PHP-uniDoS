<?php
declare(strict_types=1);

// Non-exception fatal error candidate for PHP 8.5's last_fatal_error_backtrace.
// A later early diagnostic must run on the same persistent PHP worker.
header('X-Lab-Worker-Pid: ' . getmypid());
header('X-Lab-Producer: fatal-backtrace');
function lab_fatal_backtrace_producer(): void
{
    error_log('CVE_LAB_BACKTRACE_PRODUCER pid=' . getmypid());
    trigger_error('CVE_LAB_BACKTRACE_FATAL', E_USER_ERROR);
}

lab_fatal_backtrace_producer();

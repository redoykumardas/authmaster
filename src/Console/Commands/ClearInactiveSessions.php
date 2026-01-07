<?php

namespace Redoy\AuthMaster\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Redoy\AuthMaster\Models\DeviceSession;

class ClearInactiveSessions extends Command
{
    protected $signature = 'authmaster:clear-sessions {--days=30 : Clear sessions older than X days}';
    protected $description = 'Clear inactive device sessions from the database';

    public function handle()
    {
        $days = $this->option('days');
        $cutoff = Carbon::now()->subDays($days);

        $count = DeviceSession::where('last_active_at', '<', $cutoff)->delete();

        $this->info("Cleared {$count} inactive sessions older than {$days} days.");
    }
}

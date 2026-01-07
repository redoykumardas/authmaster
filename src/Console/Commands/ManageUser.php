<?php

namespace Redoy\AuthMaster\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;

class ManageUser extends Command
{
    protected $signature = 'authmaster:manage-user {email : User email} {--password= : New password}';
    protected $description = 'Common user management tasks (currently supports password reset)';

    public function handle()
    {
        $email = $this->argument('email');
        $password = $this->option('password');

        $userModel = config('auth.providers.users.model');
        $user = $userModel::where('email', $email)->first();

        if (!$user) {
            $this->error("User with email {$email} not found.");
            return 1;
        }

        if ($password) {
            $user->password = Hash::make($password);
            $user->save();
            $this->info("Password for user {$email} has been updated.");
        } else {
            $this->info("User found: {$user->name} ({$user->email})");
        }

        return 0;
    }
}

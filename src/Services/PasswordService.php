<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class PasswordService
{
    public function sendResetLink(string $email): array
    {
        $status = Password::sendResetLink(['email' => $email]);

        if ($status === Password::RESET_LINK_SENT) {
            return ['success' => true];
        }

        return ['success' => false, 'message' => trans($status)];
    }

    public function resetPassword(array $payload): array
    {
        $status = Password::reset(
            ['email' => $payload['email'], 'password' => $payload['password'], 'token' => $payload['token']],
            function ($user, $password) {
                $user->password = Hash::make($password);
                $user->setRememberToken(Str::random(60));
                $user->save();
            }
        );

        if ($status === Password::PASSWORD_RESET) {
            return ['success' => true];
        }

        return ['success' => false, 'message' => trans($status)];
    }
}

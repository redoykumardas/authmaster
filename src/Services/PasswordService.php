<?php

namespace Redoy\AuthMaster\Services;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Redoy\AuthMaster\Contracts\PasswordServiceInterface;
use Redoy\AuthMaster\Exceptions\AuthException;

class PasswordService implements PasswordServiceInterface
{
    public function sendResetLink(string $email): void
    {
        $status = Password::sendResetLink(['email' => $email]);

        if ($status !== Password::RESET_LINK_SENT) {
            throw new AuthException(trans($status), 422);
        }
    }

    public function resetPassword(array $payload): void
    {
        $status = Password::reset(
            ['email' => $payload['email'], 'password' => $payload['password'], 'token' => $payload['token']],
            function ($user, $password) {
                $user->password = Hash::make($password);
                $user->setRememberToken(Str::random(60));
                $user->save();
            }
        );

        if ($status !== Password::PASSWORD_RESET) {
            throw new AuthException(trans($status), 422);
        }
    }
}

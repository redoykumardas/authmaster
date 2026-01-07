<?php

namespace Redoy\AuthMaster\Services;

use Redoy\AuthMaster\Contracts\ValidationManagerInterface;

class ValidationManager implements ValidationManagerInterface
{
    public function rulesForLogin(): array
    {
        return [
            'email' => 'required|email',
            'password' => 'required|string',
            'device_id' => 'sometimes|string',
        ];
    }

    public function rulesForRegister(): array
    {
        return [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|confirmed|min:8',
            'device_id' => 'sometimes|string',
            'device_name' => 'sometimes|string|max:255',
        ];
    }

    public function rulesForProfileUpdate($user): array
    {
        return [
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|email|unique:users,email,' . ($user->id ?? 'NULL'),
        ];
    }

    public function rulesForChangePassword(): array
    {
        return [
            'current_password' => 'required|string',
            'password' => 'required|string|confirmed|min:8',
        ];
    }

    public function rulesForPasswordEmail(): array
    {
        return [
            'email' => 'required|email',
        ];
    }

    public function rulesForPasswordReset(): array
    {
        return [
            'token' => 'required|string',
            'email' => 'required|email',
            'password' => 'required|string|confirmed|min:8',
        ];
    }

    public function rulesFor2FASend(): array
    {
        return [];
    }

    public function rulesFor2FAVerify(): array
    {
        return [
            'code' => 'required|string',
        ];
    }
}

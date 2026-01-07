<?php

namespace Redoy\AuthMaster\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class VerifyEmailRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        $method = config('authmaster.registration.email_verification', 'none');

        if ($method === 'otp') {
            return [
                'code' => ['required', 'string'],
                'email' => ['required', 'email'],
            ];
        }

        if ($method === 'link') {
            return [
                'token' => ['required', 'string'],
            ];
        }

        return [];
    }

    public function messages(): array
    {
        return [
            'code.required' => 'Verification code is required.',
            'email.required' => 'Email address is required.',
            'email.email' => 'Please provide a valid email address.',
            'token.required' => 'Verification token is required.',
        ];
    }
}

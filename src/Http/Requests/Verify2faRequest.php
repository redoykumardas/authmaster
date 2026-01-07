<?php

namespace Redoy\AuthMaster\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class Verify2faRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'code' => ['required', 'string'],
        ];
    }

    public function messages(): array
    {
        return [
            'code.required' => 'Verification code is required.',
        ];
    }
}

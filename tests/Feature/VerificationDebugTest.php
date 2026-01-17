<?php

namespace Redoy\AuthMaster\Tests\Feature;

use Redoy\AuthMaster\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Foundation\Auth\User;

class VerificationDebugTest extends TestCase
{

    public function test_pending_registration_verification_flow()
    {
        // Ensure pending flow is enabled
        config(['authmaster.registration.email_verification' => 'otp']);

        // 1. Register
        $this->postJson('/api/auth/register', [
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ])->assertStatus(200);

        // 2. Check if user NOT in DB
        $this->assertDatabaseMissing('users', ['email' => 'jane@example.com']);

        // 3. Verify with code (using dev_otp '123456' from config)
        $response = $this->postJson('/api/auth/verify-email', [
            'email' => 'jane@example.com',
            'code' => '123456',
            'method' => 'otp'
        ]);

        $response->assertStatus(201)
            ->assertJsonFragment(['message' => 'Email verified and account created successfully']);

        // 4. Check if user IS in DB now
        $this->assertDatabaseHas('users', ['email' => 'jane@example.com']);
    }

}

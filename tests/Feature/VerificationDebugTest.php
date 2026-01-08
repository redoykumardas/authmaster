<?php

namespace Redoy\AuthMaster\Tests\Feature;

use Redoy\AuthMaster\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Foundation\Auth\User;

class VerificationDebugTest extends TestCase
{
    public function test_existing_user_verification_fails_if_no_otp_in_cache()
    {
        // 1. Create a user manually (as if seeded)
        $userId = DB::table('users')->insertGetId([
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => bcrypt('password123'),
        ]);

        // 2. Attempt to verify without sending OTP
        $response = $this->postJson('/api/auth/verify-email', [
            'email' => 'john@example.com',
            'code' => '123456',
            'method' => 'otp'
        ]);

        // This reproduces the error reported by the user
        $response->assertStatus(422)
            ->assertJsonFragment(['message' => 'Verification code expired or not found']);
    }

    public function test_pending_registration_verification_flow()
    {
        // Ensure pending flow is enabled
        config(['authmaster.registration.verify_before_create' => true]);
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

    public function test_existing_user_verification_returns_already_verified_if_so()
    {
        // 1. Create a verified user
        DB::table('users')->insertGetId([
            'name' => 'Verified User',
            'email' => 'verified@example.com',
            'password' => bcrypt('password123'),
            'email_verified_at' => now(),
        ]);

        // 2. Attempt to verify
        $response = $this->postJson('/api/auth/verify-email', [
            'email' => 'verified@example.com',
            'code' => '123456',
            'method' => 'otp'
        ]);

        $response->assertStatus(200)
            ->assertJsonFragment(['message' => 'Email is already verified']);
    }
}

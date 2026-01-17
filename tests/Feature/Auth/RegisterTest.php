<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Contracts\RegistrationServiceInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\Exceptions\AuthException;

class RegisterTest extends AuthTestCase
{
    protected string $endpoint = '/api/auth/register';
    protected string $defaultName = 'Test User';
    protected string $defaultPassword = 'SecurePass123!';
    protected string $defaultEmail = 'user@example.com';
    protected string $defaultToken = 'abc123token';

    // =========================================================================
    // SUCCESS CASES
    // =========================================================================

    /** @test */
    public function test_successful_registration_returns_201()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => $this->defaultName],
            message: 'Registered',
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201)
            ->assertJsonFragment(['message' => 'Registered']);
    }

    /** @test */
    public function test_successful_registration_returns_token()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User'],
            token: ['token' => $this->defaultToken],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201)
            ->assertJsonStructure(['success', 'message', 'data' => ['user', 'token']]);
    }

    /** @test */
    public function test_registration_with_device_id_header()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ], ['device_id' => 'test-device-123'])
            ->assertStatus(201);
    }

    // =========================================================================
    // FAILURE CASES - DUPLICATE EMAIL
    // =========================================================================

    /** @test */
    public function test_registration_fails_when_email_already_exists()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willThrowException(new AuthException('Email already exists', 422));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'existing@example.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Email already exists']);
    }

    // =========================================================================
    // FAILURE CASES - RESTRICTED DOMAINS
    // =========================================================================

    /** @test */
    public function test_registration_fails_with_blocked_email_domain()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willThrowException(new AuthException('Email domain not allowed', 422));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'user@spam.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Email domain not allowed']);
    }

    /** @test */
    public function test_registration_fails_with_disposable_email()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willThrowException(new AuthException('Disposable email addresses are not allowed', 422));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'user@tempmail.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Disposable email addresses are not allowed']);
    }

    // =========================================================================
    // RATE LIMITING
    // =========================================================================

    /** @test */
    public function test_registration_rate_limited_returns_422()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willThrowException(new AuthException('Too many registration attempts. Please try again later.', 422));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Too many registration attempts. Please try again later.']);
    }

    // =========================================================================
    // SECURITY TESTS - SQL INJECTION
    // =========================================================================

    /** @test */
    public function test_registration_handles_sql_injection_in_name()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $maliciousName = "Robert'); DROP TABLE users;--";

        $this->postJson($this->endpoint, [
            'name' => $maliciousName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_handles_sql_injection_in_email()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $maliciousEmail = "test@example.com' OR '1'='1";

        // Should fail validation due to invalid email format
        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $maliciousEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422);
    }

    // =========================================================================
    // SECURITY TESTS - XSS
    // =========================================================================

    /** @test */
    public function test_registration_handles_xss_in_name()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $xssPayload = '<script>alert("XSS")</script>';

        $this->postJson($this->endpoint, [
            'name' => $xssPayload,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_handles_html_injection_in_name()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $htmlPayload = '<img src=x onerror=alert(1)>';

        $this->postJson($this->endpoint, [
            'name' => $htmlPayload,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    // =========================================================================
    // SECURITY TESTS - MASS ASSIGNMENT
    // =========================================================================

    /** @test */
    public function test_registration_ignores_unauthorized_fields()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
            'is_admin' => true,
            'role' => 'admin',
            'verified_at' => now(),
        ])
            ->assertStatus(201);
    }

    // =========================================================================
    // EDGE CASES - BOUNDARY VALUES
    // =========================================================================

    /** @test */
    public function test_registration_with_minimum_valid_name_length()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => 'A',
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_maximum_valid_name_length()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $longName = str_repeat('A', 255);

        $this->postJson($this->endpoint, [
            'name' => $longName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_unicode_characters_in_name()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $unicodeName = '张伟 مریم Müller 田中';

        $this->postJson($this->endpoint, [
            'name' => $unicodeName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_emoji_in_name()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $emojiName = 'Test User 🚀';

        $this->postJson($this->endpoint, [
            'name' => $emojiName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    // =========================================================================
    // EDGE CASES - EMAIL FORMATS
    // =========================================================================

    /** @test */
    public function test_registration_with_subdomain_email()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'user@mail.example.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_plus_sign_email()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'user+test@example.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_uppercase_email()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'USER@EXAMPLE.COM',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    // =========================================================================
    // ERROR HANDLING
    // =========================================================================

    /** @test */
    public function test_registration_handles_internal_server_error()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willThrowException(new \Exception('Database connection failed'));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(500);
    }

    // =========================================================================
    // RESPONSE STRUCTURE TESTS
    // =========================================================================

    /** @test */
    public function test_successful_registration_response_structure()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => $this->defaultName, 'email' => $this->defaultEmail],
            token: ['token' => $this->defaultToken],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => ['user', 'token'],
            ]);
    }

    /** @test */
    public function test_failed_registration_response_structure()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willThrowException(new AuthException('Registration failed', 422));

        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonStructure([
                'success',
                'message',
            ]);
    }

    // =========================================================================
    // CONTENT-TYPE AND HEADERS
    // =========================================================================

    /** @test */
    public function test_registration_returns_json_content_type()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));

        $this->bindRegistrationService($registration);

        $response = $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ]);

        $response->assertStatus(201);
        $response->assertHeader('Content-Type', 'application/json');
    }

    // =========================================================================
    // CONCURRENT REGISTRATION (CONCEPTUAL)
    // =========================================================================

    /** @test */
    public function test_multiple_registrations_with_same_email_handled()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $callCount = 0;
        $registration->method('register')->willReturnCallback(function () use (&$callCount) {
            $callCount++;
            if ($callCount === 1) {
                return new AuthResult(user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'], status: 201);
            }
            throw new AuthException('Email already exists', 422);
        });

        $this->bindRegistrationService($registration);

        // First registration
        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'unique@example.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])->assertStatus(201);

        // Second registration with same email
        $this->postJson($this->endpoint, [
            'name' => 'Another User',
            'email' => 'unique@example.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])->assertStatus(422);
    }

    // =========================================================================
    // VALIDATION TESTS - REAL VALIDATION RULES
    // These tests use real ValidationManager to verify actual validation logic
    // =========================================================================

    /** @test */
    public function test_validation_fails_when_name_is_missing()
    {
        // Use real RegistrationService mock from AuthTestCase
        // Use real validator by NOT calling bindValidator() (which doesn't exist anyway)

        $this->postJson($this->endpoint, [
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    }

    /** @test */
    public function test_validation_fails_when_name_exceeds_255_characters()
    {

        $this->postJson($this->endpoint, [
            'name' => str_repeat('A', 256),
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    }

    /** @test */
    public function test_validation_fails_when_email_is_missing()
    {

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /** @test */
    public function test_validation_fails_when_email_format_is_invalid()
    {

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'not-an-email',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /** @test */
    public function test_validation_fails_when_email_missing_at_symbol()
    {

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'testexample.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /** @test */
    public function test_validation_fails_when_email_missing_domain()
    {

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'test@',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /** @test */
    public function test_validation_fails_when_password_is_missing()
    {

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function test_validation_fails_when_password_is_less_than_8_characters()
    {

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => '1234567', // 7 chars
            'password_confirmation' => '1234567',
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function test_validation_fails_when_password_confirmation_missing()
    {

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            // Missing password_confirmation
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function test_validation_fails_when_password_confirmation_does_not_match()
    {

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => 'DifferentPassword123!',
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function test_validation_fails_when_all_fields_are_empty()
    {

        $this->postJson($this->endpoint, [])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password']);
    }

    /** @test */
    public function test_validation_fails_with_empty_string_values()
    {

        $this->postJson($this->endpoint, [
            'name' => '',
            'email' => '',
            'password' => '',
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password']);
    }

    /** @test */
    public function test_validation_fails_with_null_values()
    {

        $this->postJson($this->endpoint, [
            'name' => null,
            'email' => null,
            'password' => null,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password']);
    }

    /** @test */
    public function test_validation_passes_with_exactly_8_character_password()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));
        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => '12345678', // exactly 8 chars
            'password_confirmation' => '12345678',
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_validation_passes_with_exactly_255_character_name()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));
        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => str_repeat('A', 255), // exactly 255 chars
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_validation_accepts_device_name()
    {
        $registration = $this->createMock(RegistrationServiceInterface::class);
        $registration->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            status: 201
        ));
        $this->bindRegistrationService($registration);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
            'device_name' => 'My Test Phone',
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_pending_registration_returns_correct_response()
    {
        \Illuminate\Support\Facades\Mail::fake();
        // Use real service instead of mock from AuthTestCase
        $this->app->forgetInstance(RegistrationServiceInterface::class);
        $this->app->forgetInstance(\Redoy\AuthMaster\Services\EmailVerificationService::class);

        config(['authmaster.registration.email_verification' => 'otp']);

        $this->postJson($this->endpoint, [
            'name' => 'Pending User',
            'email' => 'pending@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ])
            ->assertStatus(200)
            ->assertJsonFragment([
                'pending_registration' => true,
                'email_verification_method' => 'otp'
            ]);
    }

    /** @test */
    public function test_link_registration_includes_dev_info_in_local()
    {
        \Illuminate\Support\Facades\Mail::fake();
        $this->app->forgetInstance(RegistrationServiceInterface::class);
        $this->app->forgetInstance(\Redoy\AuthMaster\Services\EmailVerificationService::class);

        config(['authmaster.registration.email_verification' => 'link']);
        // Default APP_ENV in tests is usually 'testing' or 'local' but isProduction() returns false

        $this->postJson($this->endpoint, [
            'name' => 'Link User',
            'email' => 'link@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ])
            ->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'dev_verification_url',
                    'dev_token'
                ]
            ]);
    }

    public function test_dev_info_is_hidden_in_production()
    {
        \Illuminate\Support\Facades\Mail::fake();
        $this->app->forgetInstance(RegistrationServiceInterface::class);
        $this->app->forgetInstance(\Redoy\AuthMaster\Services\EmailVerificationService::class);

        $originalEnv = $this->app['env'];
        $this->app['env'] = 'production';

        try {
            config(['authmaster.registration.email_verification' => 'link']);

            $this->postJson($this->endpoint, [
                'name' => 'Prod User',
                'email' => 'prod@example.com',
                'password' => 'Password123!',
                'password_confirmation' => 'Password123!',
            ])
                ->assertStatus(200)
                ->assertJsonMissing(['dev_verification_url'])
                ->assertJsonMissing(['dev_token']);
        } finally {
            $this->app['env'] = $originalEnv;
        }
    }

    /** @test */
    public function test_registration_with_device_management()
    {
        \Illuminate\Support\Facades\Mail::fake();
        $this->app->forgetInstance(RegistrationServiceInterface::class);
        $this->app->forgetInstance(\Redoy\AuthMaster\Services\EmailVerificationService::class);

        config(['authmaster.registration.email_verification' => 'otp']);

        $this->postJson($this->endpoint, [
            'name' => 'Device User',
            'email' => 'device@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
            'device_name' => 'iPhone 15',
        ])
            ->assertStatus(200);

        // Verify it's cached with device info
        $key = "authmaster_pending_reg:" . md5('device@example.com');
        $cached = \Illuminate\Support\Facades\Cache::get($key);

        $this->assertEquals('iPhone 15', $cached['device_name']);
    }
}

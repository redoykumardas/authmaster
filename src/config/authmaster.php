<?php

return [
    'driver' => env('AUTHMASTER_DRIVER', 'sanctum'), // jwt | passport | sanctum

    'max_devices_per_user' => env('AUTHMASTER_MAX_DEVICES', 5), // null for unlimited

    'auth_middleware' => env('AUTHMASTER_AUTH_MIDDLEWARE', 'auth:sanctum'),

    'enable_2fa' => env('AUTHMASTER_ENABLE_2FA', true),
    'enable_password_reset' => env('AUTHMASTER_ENABLE_PASSWORD_RESET', true),
    'enable_social' => env('AUTHMASTER_ENABLE_SOCIAL', true),

    'security' => [
        'max_login_attempts' => env('AUTHMASTER_MAX_LOGIN_ATTEMPTS', 5),
        'max_login_attempts_per_device' => env('AUTHMASTER_MAX_LOGIN_ATTEMPTS_PER_DEVICE', 10),
        'max_registration_attempts_per_device' => env('AUTHMASTER_MAX_REG_ATTEMPTS_PER_DEVICE', 3),
        'lockout_duration_minutes' => env('AUTHMASTER_LOCKOUT_DURATION', 15),
        'device_lockout_duration_minutes' => env('AUTHMASTER_DEVICE_LOCKOUT_DURATION', 60),
        'otp_enforcement_threshold' => env('AUTHMASTER_OTP_ENFORCE_THRESHOLD', 3),
        'notify_on_suspicious' => env('AUTHMASTER_NOTIFY_SUSPICIOUS', true),
    ],

    'social_providers' => [
        'google' => [
            'client_id' => env('AUTHMASTER_GOOGLE_CLIENT_ID'),
            'client_secret' => env('AUTHMASTER_GOOGLE_CLIENT_SECRET'),
            'redirect' => env('AUTHMASTER_GOOGLE_REDIRECT'),
            'enabled' => env('AUTHMASTER_GOOGLE_ENABLED', false),
        ],
        'facebook' => [
            'client_id' => env('AUTHMASTER_FACEBOOK_CLIENT_ID'),
            'client_secret' => env('AUTHMASTER_FACEBOOK_CLIENT_SECRET'),
            'redirect' => env('AUTHMASTER_FACEBOOK_REDIRECT'),
            'enabled' => env('AUTHMASTER_FACEBOOK_ENABLED', false),
        ],
    ],

    'otp' => [
        'length' => env('AUTHMASTER_OTP_LENGTH', 6),
        'ttl' => env('AUTHMASTER_OTP_TTL', 300), // seconds
        'force_for_all' => env('AUTHMASTER_OTP_FORCE_FOR_ALL', false),
        'resend_delay_seconds' => env('AUTHMASTER_OTP_RESEND_DELAY', 60),

        'use_queue' => env('AUTHMASTER_OTP_USE_QUEUE', true),
        'queue_name' => env('AUTHMASTER_OTP_QUEUE', 'default'),

        // Default OTP for development/testing (only used when APP_ENV != 'production')
        // Set to null to always use random OTP
        'dev_otp' => env('AUTHMASTER_DEV_OTP', '123456'),
    ],

    'tokens' => [
        'expiration' => env('AUTHMASTER_TOKEN_EXPIRATION', 60 * 24), // minutes
    ],

    'registration' => [
        // Email verification method: 'none', 'otp', or 'link'
        'email_verification' => env('AUTHMASTER_EMAIL_VERIFICATION', 'link'),

        // URL for email verification link (only used when email_verification = 'link')
        // If you are using a frontend, set this to your frontend verification page.
        // If testing via API directly, point this to the API endpoint: /api/auth/verify-email
        'verification_url' => env('AUTHMASTER_VERIFICATION_URL', '/api/auth/verify-email'),

        // Verification token/OTP expiration in seconds
        'verification_expires' => env('AUTHMASTER_VERIFICATION_EXPIRES', 3600), // 1 hour

        // Default Token for development/testing (only used when APP_ENV != 'production')
        // Set to null to always use random Token
        'dev_token' => env('AUTHMASTER_DEV_TOKEN', 'dev-verification-token'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Sanctum Configuration (Merged)
    |--------------------------------------------------------------------------
    |
    | Configuration options specific to the Sanctum driver.
    |
    */
    'sanctum' => [
        'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS', sprintf(
            '%s%s',
            'localhost,localhost:3000,127.0.0.1,127.0.0.1:8000,::1',
            \Laravel\Sanctum\Sanctum::currentApplicationUrlWithPort()
        ))),
        'guard' => ['web'],
        'expiration' => null,
        'token_prefix' => env('SANCTUM_TOKEN_PREFIX', ''),
        'middleware' => [
            'authenticate_session' => \Laravel\Sanctum\Http\Middleware\AuthenticateSession::class,
            'encrypt_cookies' => \Illuminate\Cookie\Middleware\EncryptCookies::class,
            'validate_csrf_token' => \Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class,
        ],
    ],
];

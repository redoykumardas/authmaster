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
        'lockout_duration_minutes' => env('AUTHMASTER_LOCKOUT_DURATION', 15),
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

        // Default OTP for development/testing (only used when APP_ENV != 'production')
        // Set to null to always use random OTP
        'dev_otp' => env('AUTHMASTER_DEV_OTP', '123456'),
    ],

    'tokens' => [
        'expiration' => env('AUTHMASTER_TOKEN_EXPIRATION', 60 * 24), // minutes
    ],

    'registration' => [
        // Email verification method: 'none', 'otp', or 'link'
        'email_verification' => env('AUTHMASTER_EMAIL_VERIFICATION', 'otp'),

        // URL for email verification link (only used when email_verification = 'link')
        'verification_url' => env('AUTHMASTER_VERIFICATION_URL', '/verify-email'),

        // Verification token/OTP expiration in seconds
        'verification_expires' => env('AUTHMASTER_VERIFICATION_EXPIRES', 3600), // 1 hour

        // If true, user account is NOT created until email is verified (more secure)
        // If false, account is created immediately and user must verify later
        'verify_before_create' => env('AUTHMASTER_VERIFY_BEFORE_CREATE', true),

        // Default Token for development/testing (only used when APP_ENV != 'production')
        // Set to null to always use random Token
        'dev_token' => env('AUTHMASTER_DEV_TOKEN', 'dev-verification-token'),
    ],
];

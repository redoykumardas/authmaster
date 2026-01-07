# AuthMaster — Usage & Developer Guide

This folder contains the `redoy/authmaster` Laravel package. The package implements a service-driven authentication layer (routes, helpers, services, middleware) and includes a local test-suite using Orchestra Testbench.

**This README** covers: installation, configuration, usage examples, testing, and CI recommendations.

**Install (consuming application)**

If published on Packagist you would run:

```bash
composer require redoy/authmaster@dev
```

If you are developing locally within a Laravel application (monorepo or local package), add a `path` repository to your application's `composer.json` and require it:

```json
"repositories": [
	{
		"type": "path",
		"url": "./packages/redoy/authmaster"
	}
]

// then
composer require redoy/authmaster:*
```

After installation, register the service provider (if not using package discovery):

```php
// config/app.php
'providers' => [
		// ...
		Redoy\AuthMaster\AuthMasterServiceProvider::class,
];
```

**Publish package assets**

Publish configuration, migrations and views (email templates):

```bash
php artisan vendor:publish --provider="Redoy\AuthMaster\AuthMasterServiceProvider" --tag=config
php artisan vendor:publish --provider="Redoy\AuthMaster\AuthMasterServiceProvider" --tag=migrations
php artisan vendor:publish --provider="Redoy\AuthMaster\AuthMasterServiceProvider" --tag=views
```

Run migrations after publishing (or let the host application manage migrations):

```bash
php artisan migrate
```

**Routes & Middleware**

The package loads routes under the `/auth` prefix. Public example endpoints include:

- `POST /auth/login`
- `POST /auth/register`
- `POST /auth/password/email`
- `POST /auth/password/reset`
- `POST /auth/2fa/verify`
- `POST /auth/social/{provider}`
- `GET  /auth/social/{provider}/callback`

Protected endpoints (use `authmaster.auth_middleware` to control guard):

- `POST /auth/logout`
- `POST /auth/logout/all`
- `GET  /auth/profile`
- `PATCH /auth/profile`
- `POST /auth/password/change`
- `POST /auth/2fa/send`

The package registers a middleware alias `authmaster.attach_device` for `AttachDeviceId` middleware. You can use it in your routes or globally:

```php
Route::middleware(['authmaster.attach_device'])->group(function () {
		// your routes
});
```

**Helpers**

Convenience helper functions provided by the package:

- `authmaster_device_id(Request $request = null): string` — returns `device_id` header if present or a sha256(ip|userAgent) fallback.
- `authmaster_token_response(array $tokenData = []): array` — standardized token response array with `access_token`, `token_type`, and `expires_at`.

Usage example:

```php
$deviceId = authmaster_device_id();
$tokenResponse = authmaster_token_response(['access_token' => 'abc', 'expires_at' => now()->addDay()]);
```

**Services / Public API**

The package exposes services bound in the container (see `AuthMasterServiceProvider`):

- `Redoy\AuthMaster\Services\AuthManager` — high-level auth orchestration (login, register, 2FA, social, password flows).
- `Redoy\AuthMaster\Services\EmailVerificationService` — handles OTP and Link-based verification flows (including secure pending registration).
- `Redoy\AuthMaster\Services\TokenService` — token creation logic (supports Sanctum/Passport if present, otherwise fallback token generation).
- `Redoy\AuthMaster\Services\DeviceSessionService` — manage per-user device sessions in cache.
- `Redoy\AuthMaster\Services\TwoFactorService` — generate/verify OTPs and send via mail.
- `Redoy\AuthMaster\Services\SocialLoginService` — social redirect/callback flows (requires Laravel Socialite for full functionality).

Example using `TokenService`:

```php
$tokenSvc = app(\Redoy\AuthMaster\Services\TokenService::class);
$tokenData = $tokenSvc->createTokenForUser($user, authmaster_device_id());
```

Notes:
- `SocialLoginService` will return a helpful error if Socialite is not installed. To enable social providers, configure `authmaster.social_providers` in the published config and install `laravel/socialite`.
- `TokenService` tries to use `$user->createToken()` (Sanctum/Passport). If the user model lacks that method, it generates a random token string and expects `DeviceSessionService` to persist session metadata.

**Configuration**

Defaults are in `src/config/authmaster.php` (published to `config/authmaster.php`). For detailed registration flows, see [Registration Guide](docs/REGISTRATION.md).

Important keys include:

- `driver` — token driver (sanctum, passport, etc.)
- `auth_middleware` — guard middleware used for protected routes (defaults to `auth:sanctum` in the package). For quick integration you can set `authmaster.auth_middleware` to `api` or another guard in `config/authmaster.php`.
- `otp` — 2FA settings: `length`, `ttl`, `force_for_all`.
- `device_session_ttl` and `max_devices_per_user` — control device session caching and enforcement.

Adjust these values in `config/authmaster.php` to suit your application's requirements.

**Testing the package (developer)**

This package includes a local test-suite using Orchestra Testbench. To run tests locally from the package root:

```bash
cd packages/redoy/authmaster
composer install
./vendor/bin/phpunit -c phpunit.xml
```

Notes:
- Tests use an in-memory SQLite database and the `array` cache driver for predictable behavior.
- `Orchestra/Testbench` is included in `require-dev` so tests boot a lightweight Laravel environment.

**CI recommendations**

Create a GitHub Actions workflow that runs on push and pull requests, with a PHP matrix (for example 8.1, 8.2, 8.3). Steps should:

- Checkout
- Setup PHP with required extensions
- `composer install` in `packages/redoy/authmaster`
- Run `./vendor/bin/phpunit -c phpunit.xml`
- Run static analysis (`phpstan`/`psalm`) and linting
- Optionally upload coverage to Codecov

Example (skeleton):

```yaml
name: CI
on: [push, pull_request]
jobs:
	test:
		runs-on: ubuntu-latest
		strategy:
			matrix:
				php: [8.1, 8.2, 8.3]
		steps:
			- uses: actions/checkout@v4
			- name: Setup PHP
				uses: shivammathur/setup-php@v2
				with:
					php-version: ${{ matrix.php }}
			- name: Install composer deps
				run: |
					cd packages/redoy/authmaster
					composer install --no-interaction --prefer-dist
			- name: Run tests
				run: ./vendor/bin/phpunit -c phpunit.xml
```

**Contributing**

1. Fork the repo and create a feature branch.
2. Add tests for any bugfix or feature.
3. Run the package test-suite and ensure all tests pass.
4. Open a PR describing changes and test coverage.

**License**

MIT — see `LICENSE`.

If you want, I can also generate a ready-to-use GitHub Actions workflow file and add more concrete usage examples (controller snippets, middleware registration, or sample config). Which would you like next?

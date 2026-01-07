# 🔐 Registration Features

AuthMaster provides a flexible and secure registration system designed for modern APIs.

## 1. Secure "Verify Before Create" (Pending Flow)
To prevent "email squatting" and ensure database integrity, AuthMaster can be configured to verify users before account creation.

- **Mechanism**: User data is stored in a secure cache (AES encrypted/hashed) until verification.
- **Benefits**: No "zombie" accounts for unverified users. No "Email already taken" errors for failed registrations.
- **Configuration**: Set `verify_before_create => true` in `config/authmaster.php`.

## 2. Verification Methods
AuthMaster supports three registration modes:

| Method | Description | Configuration |
| :--- | :--- | :--- |
| **OTP** | Sends a 6-digit numeric code to the email. | `'email_verification' => 'otp'` |
| **Link** | Sends a secure clickable link (supports GET/POST). | `'email_verification' => 'link'` |
| **None** | Account is created immediately. | `'email_verification' => 'none'` |

## 3. Link Verification (GET/POST)
Verification links are flexible and work in both browser and API contexts:
- **GET support**: Users can click directly from their email.
- **POST support**: Frontends can capture the token and verify via API.
- **Endpoint**: `/api/auth/verify-email`

## 4. Developer Helpers (Environment Aware)
AuthMaster streamlines development by surfacing verification data in non-production environments.

> [!IMPORTANT]
> These helpers are **strictly disabled** when `APP_ENV=production`.

- **Dev OTP**: Use a fixed code (default: `123456`) instead of waiting for emails.
- **Dev Link**: Registration response includes `dev_verification_url` and `dev_token` for instant testing.
- **Randomization**: In production, random secure strings are always used regardless of config settings.

## 5. Mails and Customization
- **Mailables**: Pre-built `SendOtpMail` and `VerificationLinkMail`.
- **Custom Welcome**: Automatically sends a `WelcomeMail` post-verification if the class exists.
- **Expiry**: Set verification TTL in seconds via `verification_expires`.
- **Length**: Configure OTP code length via `otp.length`.

## 6. Events Integration
AuthMaster dispatches the standard Laravel `Illuminate\Auth\Events\Registered` event only *after* successful verification (in pending flow) or immediate registration.

## 📱 7. Device Management during Registration
AuthMaster allows you to securely link a device during the registration process:
- **Parameter**: Provide a `device_name` (e.g., "iPhone 15", "Web Browser") in your registration request.
- **Persistence**: The device name is securely cached during the pending verification phase.
- **Auto-Session**: Once verified, a device session is automatically created, and any `max_devices_per_user` limits are strictly enforced.
- **Flexible IDs**: Works with your custom `device_id` header or falls back to IP/User-Agent hashing.

---
*For testing these flows, refer to the [Postman Collection](authmaster_postman_collection.json).*

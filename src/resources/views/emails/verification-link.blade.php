<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <title>Verify Your Email</title>
</head>

<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #2563eb;">Verify Your Email Address</h2>

        <p>Hello {{ $user->name ?? 'User' }},</p>

        <p>Thank you for registering. Please click the button below to verify your email address:</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{{ $verificationUrl }}"
                style="background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Verify Email Address
            </a>
        </div>

        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #2563eb;">{{ $verificationUrl }}</p>

        <p>This link will expire in {{ config('authmaster.registration.verification_expires', 3600) / 60 }} minutes.</p>

        <p>If you did not create an account, no further action is required.</p>

        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">

        <p style="color: #666; font-size: 12px;">
            This email was sent automatically. Please do not reply.
        </p>
    </div>
</body>

</html>
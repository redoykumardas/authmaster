<?php

namespace Redoy\AuthMaster\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Redoy\AuthMaster\Traits\ApiResponse;
use Redoy\AuthMaster\Services\AuthManager;
use Redoy\AuthMaster\Services\ValidationManager;

class AuthController extends Controller
{
    use ApiResponse;
    use ValidatesRequests;

    protected AuthManager $authManager;
    protected ValidationManager $validator;

    public function __construct(AuthManager $authManager, ValidationManager $validator)
    {
        $this->authManager = $authManager;
        $this->validator = $validator;
    }

    public function login(Request $request)
    {
        $this->validate($request, $this->validator->rulesForLogin());

        $result = $this->authManager->login($request);

        if ($result['success']) {
            return $this->success($result['data'], 'Logged in', 200);
        }

        return $this->error($result['message'] ?? 'Unauthorized', 401, $result['errors'] ?? []);
    }

    public function register(Request $request)
    {
        $this->validate($request, $this->validator->rulesForRegister());
        $result = $this->authManager->register($request);
        if ($result['success']) {
            return $this->success($result['data'], 'Registered', 201);
        }
        return $this->error($result['message'] ?? 'Registration failed', 422, $result['errors'] ?? []);
    }

    public function logout(Request $request)
    {
        $this->authManager->logoutCurrentDevice($request);
        return $this->success([], 'Logged out');
    }

    public function logoutAll(Request $request)
    {
        $this->authManager->logoutAllDevices($request);
        return $this->success([], 'Logged out from all devices');
    }

    public function profile(Request $request)
    {
        $user = $request->user();
        return $this->success(['user' => $user]);
    }

    public function updateProfile(Request $request)
    {
        $this->validate($request, $this->validator->rulesForProfileUpdate($request->user()));
        $user = $this->authManager->updateProfile($request->user(), $request->only(['name', 'email']));
        return $this->success(['user' => $user], 'Profile updated');
    }

    public function changePassword(Request $request)
    {
        $this->validate($request, $this->validator->rulesForChangePassword());
        $result = $this->authManager->changePassword($request->user(), $request->all());
        if ($result['success']) {
            return $this->success([], 'Password changed');
        }
        return $this->error($result['message'] ?? 'Failed', 422, $result['errors'] ?? []);
    }

    public function forgotPassword(Request $request)
    {
        $this->validate($request, $this->validator->rulesForPasswordEmail());
        $result = $this->authManager->sendPasswordResetLink($request->only('email'));
        if ($result['success']) {
            return $this->success([], 'Reset email sent');
        }
        return $this->error($result['message'] ?? 'Failed to send', 422);
    }

    public function resetPassword(Request $request)
    {
        $this->validate($request, $this->validator->rulesForPasswordReset());
        $result = $this->authManager->resetPassword($request->all());
        if ($result['success']) {
            return $this->success([], 'Password reset');
        }
        return $this->error($result['message'] ?? 'Failed', 422, $result['errors'] ?? []);
    }

    public function send2fa(Request $request)
    {
        $this->validate($request, $this->validator->rulesFor2FASend());
        $result = $this->authManager->sendTwoFactor($request->user());
        if ($result['success']) {
            return $this->success([], 'OTP sent');
        }
        return $this->error($result['message'] ?? 'Failed', 422);
    }

    public function verify2fa(Request $request)
    {
        $this->validate($request, $this->validator->rulesFor2FAVerify());
        $result = $this->authManager->verifyTwoFactor($request->user(), $request->input('code'));
        if ($result['success']) {
            return $this->success([], 'OTP verified');
        }
        return $this->error($result['message'] ?? 'Invalid code', 422);
    }

    public function socialRedirect(Request $request, $provider)
    {
        $result = $this->authManager->socialRedirect($provider);
        if (isset($result['redirect'])) {
            return $result['redirect'];
        }
        return $this->error($result['message'] ?? 'Provider not available', 400);
    }

    public function socialCallback(Request $request, $provider)
    {
        $result = $this->authManager->handleSocialCallback($provider, $request);
        if ($result['success']) {
            return $this->success($result['data'], 'Social login successful');
        }
        return $this->error($result['message'] ?? 'Failed', 400);
    }
}

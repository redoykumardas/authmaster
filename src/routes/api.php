<?php

use Illuminate\Support\Facades\Route;
use Redoy\AuthMaster\Http\Controllers\AuthController;

// Public routes
Route::group(['prefix' => 'auth', 'middleware' => ['api']], function () {
    Route::post('login', [AuthController::class, 'login']);
    Route::post('register', [AuthController::class, 'register']);

    Route::post('password/email', [AuthController::class, 'forgotPassword']);
    Route::post('password/reset', [AuthController::class, 'resetPassword']);

    Route::post('social/{provider}', [AuthController::class, 'socialRedirect']);
    Route::get('social/{provider}/callback', [AuthController::class, 'socialCallback']);

    // 2FA endpoints can be used in both flows; keep public for login flow and protected via token for user flow
    Route::post('2fa/verify', [AuthController::class, 'verify2fa']);
});

// Protected routes
$authMiddleware = config('authmaster.auth_middleware', 'auth:sanctum');
Route::group(['prefix' => 'auth', 'middleware' => ['api', $authMiddleware]], function () {
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('logout/all', [AuthController::class, 'logoutAll']);
    Route::get('profile', [AuthController::class, 'profile']);
    Route::patch('profile', [AuthController::class, 'updateProfile']);

    Route::post('password/change', [AuthController::class, 'changePassword']);

    Route::post('2fa/send', [AuthController::class, 'send2fa']);
});

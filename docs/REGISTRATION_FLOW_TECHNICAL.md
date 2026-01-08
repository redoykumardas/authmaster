# 🚀 Registration API: Technical Flow & Coding Pattern

This document provides a step-by-step technical breakdown of the `{{base_url}}/auth/register` API in the **AuthMaster** package.

## 🏗 Coding Pattern Overview

AuthMaster follows a strict **Service-Pattern** with **Data Transfer Objects (DTOs)** and **Interface-based Injection**. This ensures high testability and separation of concerns.

The flow follows this path:
`Route` ➔ `Request (Validation)` ➔ `Controller` ➔ `DTO` ➔ `Service` ➔ `Manager` ➔ `Result (Response)`

---

## 🛤 Step-by-Step Execution Flow

### 1. Route Definition
The entry point is defined in `src/routes/api.php`:
```php
Route::post('register', [AuthController::class, 'register']);
```

### 2. Request Validation
Incoming data is validated by `Redoy\AuthMaster\Http\Requests\RegisterRequest`.
- **Fields**: `name`, `email`, `password`, `password_confirmation`, `device_name`.
- **Rules**: Validates field types, email uniqueness, and password matching.

### 3. Controller Action
`AuthController@register` receives the validated request. It doesn't contain business logic; it merely bridges the Request to the Service.
```php
public function register(RegisterRequest $request)
{
    // RegisterData::fromRequest converts the Request into a clean DTO
    return $this->registrationService->register(
        RegisterData::fromRequest($request)
    );
}
```

### 4. DTO Transformation
Before reaching the Service, data is transformed into a `RegisterData` DTO.
- **Location**: `Redoy\AuthMaster\DTOs\RegisterData`
- **Goal**: Collects validated inputs + metadata like `ipAddress` and `deviceId` (automatically hashed from IP/User-Agent if not provided).

### 5. Service Logic (`RegistrationService`)
This is where the business rules live. The `register` method handles:
1.  **Rate Limiting**: Checks `SecurityService` to prevent registration spam.
2.  **Flow Branching**:
    - **Pending Flow**: If `verify_before_create` is enabled, it stores data in cache and sends verification.
    - **Standard Flow**: Creates the user in the database immediately.
3.  **Email Verification**: Triggers OTP or Link sending via `EmailVerificationService`.

### 6. Session Finalization (`AuthManager`)
Once the user is created (or verified), the `AuthManager` handles:
- Creating the Sanctum token.
- Recording the device information (IP, Device Name) in the `device_trackings` table.

### 7. Response (`AuthResult`)
The service returns an `AuthResult` object.
- **Location**: `Redoy\AuthMaster\DTOs\AuthResult`
- **Pattern**: Implements `Responsable`. When returned from a controller, Laravel automatically converts it to a JSON response with the appropriate HTTP status code.

---

## 🛠 Summary of Pattern Benefits

| Pattern | Benefit |
| :--- | :--- |
| **FormRequests** | Keeps controllers clean and ensures data integrity. |
| **DTOs** | Ensures the Service Layer is not dependent on HTTP Request objects. |
| **Interface Injections** | Allows swapping implementations without breaking callers. |
| **Responsable DTOs** | Standardizes API responses across the entire package. |

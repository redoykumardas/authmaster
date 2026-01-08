# 📔 AuthMaster: Deep-Dive Codebase Guide

This guide explains the architecture, coding patterns, and internal flows of the **AuthMaster** package. It is designed to help you understand how every piece fits together.

---

## 📂 1. Directory Structure & Purpose

| Directory | Purpose |
| :--- | :--- |
| **`src/Contracts`** | Interfaces that define the "rules" for every service. Ensures testability and easy swapping. |
| **`src/Services`** | The "Brain" of the package. Contains all business logic (Registration, Login, Security). |
| **`src/DTOs`** | **Data Transfer Objects**. Clean containers for data passing between layers. |
| **`src/Http/Requests`** | Laravel FormRequests for input validation. |
| **`src/Http/Controllers`** | Traffic controllers. They bridge HTTP requests to the Services. |
| **`src/routes`** | API endpoint definitions. |

---

## 🏗 2. Core Coding Patterns

### A. Dependency Injection (DI)
The package never uses `new MyService()`. Instead, objects are "injected" through constructors.
- **Example**: `RegistrationService` asks for `AuthManagerInterface` in its constructor. 
- **Benefit**: You can swap the implementation in `AuthMasterServiceProvider` without touching the actual service code.

### B. The DTO Pattern (Data Transfer Objects)
Instead of passing the raw `$request` object through your code, we convert it into a **DTO**.
- **Process**: `Controller` -> `DTO::fromRequest($request)` -> `Service`.
- **Benefit**: The Service Layer doesn't care about HTTP; it only cares about the clean data inside the DTO.

### C. The Result Pattern (`AuthResult`)
Every significant method returns an `AuthResult` object.
- **Location**: `src/DTOs/AuthResult.php`
- **Benefit**: Standardizes responses. Since it implements `Responsable`, Laravel automatically converts it to JSON when returned from a controller.

---

## 🛤 3. Step-by-Step Flow: Registration

How a user goes from a POST request to a Database entry:

1.  **Entry**: User hits `POST /api/auth/register`.
2.  **Validation**: `RegisterRequest` checks if the email is unique and password is confirmed.
3.  **DTO**: `AuthController` calls `RegisterData::fromRequest()`. This captures the validated input + IP Address + Device Name.
4.  **Service**: `RegistrationService@register` is called.
    -   **Gatekeeper**: `SecurityService` checks if this IP is spamming registrations.
    -   **Decision**: 
        -   *Pending Flow*: Data is cached, and a verification OTP/Link is sent. User is NOT in DB yet.
        -   *Standard Flow*: User is created immediately in the `users` table.
5.  **Tracking**: If successful, `AuthManager` records the login in the `device_trackings` table.

---

## 🔐 4. Step-by-Step Flow: Login

1.  **Entry**: User hits `POST /api/auth/login`.
2.  **Gatekeeper**: `SecurityService` checks if the user/IP is currently locked out after too many failures.
3.  **Attempt**: `Auth::attempt()` checks the credentials.
4.  **2FA Check**: `TwoFactorService` checks if the user has 2FA enabled. If yes, an OTP is sent and an error is thrown to stop the login.
5.  **Finalize**:
    -   Sanctum generates a token.
    -   `DeviceSessionService` records the browser/machine info.
    -   `LoginSuccessful` event is dispatched.

---

## 🛡 5. Security & Device Management

### Rate Limiting
Managed by `SecurityService`. It uses Laravel's Cache to track attempts per Email, IP, and Device ID.
- **Global limit**: Max login attempts.
- **Device limit**: Prevents one machine from attacking multiple accounts.

### Device ID Hashing
If your frontend doesn't provide a `device_id` header, the package automatically generates one in the DTO:
```php
hash('sha256', $ip . '|' . $userAgent)
```
This ensures we can track sessions accurately even for web browsers.

---

## 💡 Pro-Tips for Developers

- **Customizing Emails**: Look in `src/Mail`. You can publish the views to change the HTML/CSS of the OTP and Link emails.
- **Adding logic**: If you want to do something whenever a user logs in, create a Listener for the `Redoy\AuthMaster\Events\LoginSuccessful` event.
- **Swapping Drivers**: You can change the behavior of the package by updating `config/authmaster.php`.

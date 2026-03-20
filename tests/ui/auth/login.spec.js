//
//  Mervyn Teo Zi Yan, A0273039A
//
// UI test: Login page (pages/Auth/Login.js)
//
// Tests cover:
//  1. Form renders with email, password fields, forgot-password button, login button
//  2. Successful login → success toast + redirect to home + auth persisted in localStorage
//  3. Server-side error (wrong credentials) → error toast
//  4. Network error → generic error toast
//  5. Forgot Password button navigates to /forgot-password
//  6. Loading state shown while request is in-flight
//  7. After login, redirect respects location.state (e.g. originally tried to visit /cart)
//

import { test, expect } from "@playwright/test";

const LOGIN_ROUTE = "/login";

test.use({ storageState: { cookies: [], origins: [] } });

test.describe.serial("UI: Login page", () => {
  test("renders all form elements", async ({ page }) => {
    await page.goto(LOGIN_ROUTE);

    await expect(page.getByRole("heading", { name: /login form/i })).toBeVisible();
    await expect(page.getByPlaceholder("Enter Your Email")).toBeVisible();
    await expect(page.getByPlaceholder("Enter Your Password")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /forgot password/i })
    ).toBeVisible();
    await expect(page.getByRole("button", { name: /^login$/i })).toBeVisible();
  });

  test("successful login shows toast, stores auth in localStorage, and redirects to home", async ({
    page,
  }) => {
    const fakeUser = { name: "Test Admin", email: "test@admin.com", phone: "91234567", role: 1 };
    const fakeToken = "fake-jwt-token";

    await page.route("**/api/v1/auth/login", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          message: "login successfully",
          user: fakeUser,
          token: fakeToken,
        }),
      });
    });

    await page.goto(LOGIN_ROUTE);
    await page.getByPlaceholder("Enter Your Email").fill("test@admin.com");
    await page.getByPlaceholder("Enter Your Password").fill("test@admin.com");
    await page.getByRole("button", { name: /^login$/i }).click();

    // Success toast
    await expect(page.getByText(/login successfully/i)).toBeVisible({ timeout: 5000 });

    // Redirect to home
    await page.waitForURL("/", { timeout: 5000 });
    expect(page.url()).toMatch(/\/$/);

    // Auth stored in localStorage
    const stored = await page.evaluate(() => localStorage.getItem("auth"));
    expect(stored).not.toBeNull();
    const parsed = JSON.parse(stored);
    expect(parsed.token).toBe(fakeToken);
    expect(parsed.user.email).toBe(fakeUser.email);
  });

  test("shows error toast on invalid credentials (server returns failure)", async ({
    page,
  }) => {
    await page.route("**/api/v1/auth/login", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: false,
          message: "Invalid email or password",
        }),
      });
    });

    await page.goto(LOGIN_ROUTE);
    await page.getByPlaceholder("Enter Your Email").fill("wrong@example.com");
    await page.getByPlaceholder("Enter Your Password").fill("wrongpassword");
    await page.getByRole("button", { name: /^login$/i }).click();

    await expect(page.getByText(/invalid email or password/i)).toBeVisible({
      timeout: 5000,
    });

    // Should stay on login page
    expect(page.url()).toContain("/login");
  });

  test("shows generic error toast on network failure", async ({ page }) => {
    await page.route("**/api/v1/auth/login", async (route) => {
      await route.abort("failed");
    });

    await page.goto(LOGIN_ROUTE);
    await page.getByPlaceholder("Enter Your Email").fill("test@example.com");
    await page.getByPlaceholder("Enter Your Password").fill("password123");
    await page.getByRole("button", { name: /^login$/i }).click();

    await expect(page.getByText(/something went wrong/i)).toBeVisible({
      timeout: 5000,
    });
  });

  test("Forgot Password button navigates to /forgot-password", async ({ page }) => {
    await page.goto(LOGIN_ROUTE);
    await page.getByRole("button", { name: /forgot password/i }).click();
    await page.waitForURL("**/forgot-password", { timeout: 5000 });
    expect(page.url()).toContain("/forgot-password");
  });

  test("submit button shows loading state while request is in-flight", async ({
    page,
  }) => {
    await page.route("**/api/v1/auth/login", async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 800));
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          message: "login successfully",
          user: { name: "Test", email: "test@admin.com", phone: "91234567", role: 1 },
          token: "fake-token",
        }),
      });
    });

    await page.goto(LOGIN_ROUTE);
    await page.getByPlaceholder("Enter Your Email").fill("test@admin.com");
    await page.getByPlaceholder("Enter Your Password").fill("test@admin.com");
    await page.getByRole("button", { name: /^login$/i }).click();

    // Button should switch to "Logging in..." and be disabled
    const btn = page.getByRole("button", { name: /logging in/i });
    await expect(btn).toBeVisible({ timeout: 2000 });
    await expect(btn).toBeDisabled();
  });
});

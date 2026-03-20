//
//  Mervyn Teo Zi Yan, A0273039A
//
// UI test: Register page (pages/Auth/Register.js)
//
// Tests cover:
//  1. Form renders with all required fields
//  2. Successful registration → success toast + redirect to /login
//  3. Server-side error (e.g. duplicate email) → error toast shown
//  4. Network error → generic error toast
//  5. Loading state shown while request is in-flight
//

import { test, expect } from "@playwright/test";

const REGISTER_ROUTE = "/register";

test.use({ storageState: { cookies: [], origins: [] } });

test.describe.serial("UI: Register page", () => {
  test("renders all form fields and submit button", async ({ page }) => {
    await page.goto(REGISTER_ROUTE);

    await expect(page.getByRole("heading", { name: /register form/i })).toBeVisible();
    await expect(page.getByPlaceholder("Enter Your Name")).toBeVisible();
    await expect(page.getByPlaceholder("Enter Your Email")).toBeVisible();
    await expect(page.getByPlaceholder("Enter Your Password")).toBeVisible();
    await expect(page.getByPlaceholder("Enter Your Phone")).toBeVisible();
    await expect(page.getByPlaceholder("Enter Your Address")).toBeVisible();
    await expect(page.locator("#exampleInputDOB1")).toBeVisible();
    await expect(page.getByPlaceholder("What is Your Favorite sports")).toBeVisible();
    await expect(page.getByRole("button", { name: /register/i })).toBeVisible();
  });

  test("shows success toast and redirects to /login on successful registration", async ({
    page,
  }) => {
    // Stub the register endpoint to return success
    await page.route("**/api/v1/auth/register", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          message: "User Register Successfully",
        }),
      });
    });

    await page.goto(REGISTER_ROUTE);

    await page.getByPlaceholder("Enter Your Name").fill("Test User");
    await page.getByPlaceholder("Enter Your Email").fill("testuser@example.com");
    await page.getByPlaceholder("Enter Your Password").fill("Password123");
    await page.getByPlaceholder("Enter Your Phone").fill("91234567");
    await page.getByPlaceholder("Enter Your Address").fill("123 Test Street");
    await page.locator("#exampleInputDOB1").fill("2000-01-01");
    await page.getByPlaceholder("What is Your Favorite sports").fill("Football");

    await page.getByRole("button", { name: /register/i }).click();

    // Success toast should appear
    await expect(
      page.getByText(/register successfully/i)
    ).toBeVisible({ timeout: 5000 });

    // Should redirect to /login
    await page.waitForURL("**/login", { timeout: 5000 });
    expect(page.url()).toContain("/login");
  });

  test("shows error toast when server returns failure (e.g. duplicate email)", async ({
    page,
  }) => {
    await page.route("**/api/v1/auth/register", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: false,
          message: "Already registered, please login",
        }),
      });
    });

    await page.goto(REGISTER_ROUTE);

    await page.getByPlaceholder("Enter Your Name").fill("Test User");
    await page.getByPlaceholder("Enter Your Email").fill("duplicate@example.com");
    await page.getByPlaceholder("Enter Your Password").fill("Password123");
    await page.getByPlaceholder("Enter Your Phone").fill("91234567");
    await page.getByPlaceholder("Enter Your Address").fill("123 Test Street");
    await page.locator("#exampleInputDOB1").fill("2000-01-01");
    await page.getByPlaceholder("What is Your Favorite sports").fill("Football");

    await page.getByRole("button", { name: /register/i }).click();

    await expect(
      page.getByText(/already registered/i)
    ).toBeVisible({ timeout: 5000 });

    // Should NOT redirect — still on register page
    expect(page.url()).toContain("/register");
  });

  test("shows generic error toast on network failure", async ({ page }) => {
    await page.route("**/api/v1/auth/register", async (route) => {
      await route.abort("failed");
    });

    await page.goto(REGISTER_ROUTE);

    await page.getByPlaceholder("Enter Your Name").fill("Test User");
    await page.getByPlaceholder("Enter Your Email").fill("test@example.com");
    await page.getByPlaceholder("Enter Your Password").fill("Password123");
    await page.getByPlaceholder("Enter Your Phone").fill("91234567");
    await page.getByPlaceholder("Enter Your Address").fill("123 Test Street");
    await page.locator("#exampleInputDOB1").fill("2000-01-01");
    await page.getByPlaceholder("What is Your Favorite sports").fill("Football");

    await page.getByRole("button", { name: /register/i }).click();

    await expect(
      page.getByText(/something went wrong/i)
    ).toBeVisible({ timeout: 5000 });
  });

  test("submit button shows loading state while request is in-flight", async ({
    page,
  }) => {
    // Delay the response so we can observe the loading state
    await page.route("**/api/v1/auth/register", async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 800));
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, message: "User Register Successfully" }),
      });
    });

    await page.goto(REGISTER_ROUTE);

    await page.getByPlaceholder("Enter Your Name").fill("Test User");
    await page.getByPlaceholder("Enter Your Email").fill("test@example.com");
    await page.getByPlaceholder("Enter Your Password").fill("Password123");
    await page.getByPlaceholder("Enter Your Phone").fill("91234567");
    await page.getByPlaceholder("Enter Your Address").fill("123 Test Street");
    await page.locator("#exampleInputDOB1").fill("2000-01-01");
    await page.getByPlaceholder("What is Your Favorite sports").fill("Football");

    await page.getByRole("button", { name: /register/i }).click();

    // Button should change to "Registering..." and be disabled
    const btn = page.getByRole("button", { name: /registering/i });
    await expect(btn).toBeVisible({ timeout: 2000 });
    await expect(btn).toBeDisabled();
  });
});

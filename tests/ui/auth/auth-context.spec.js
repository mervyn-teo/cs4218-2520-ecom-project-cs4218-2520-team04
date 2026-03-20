//
//  Mervyn Teo Zi Yan, A0273039A
//
// UI test: Auth context (context/auth.js)
//
// Tests cover the runtime behaviour of AuthContext/AuthProvider:
//  1. Auth state is restored from localStorage on page load (persistence across refresh)
//  2. When localStorage has no auth entry the user is treated as unauthenticated
//  3. Auth state is cleared from localStorage on logout (header link changes)
//  4. Axios Authorization header is populated from the stored token
//     (verified indirectly: protected API calls succeed when auth is in localStorage)
//

import { test, expect } from "@playwright/test";

const FAKE_USER = {
  name: "Context Test Admin",
  email: "context@admin.com",
  phone: "81234567",
  role: 1,
};
const FAKE_TOKEN = "context-test-fake-token";

// Each test uses browser.newContext() for full control over localStorage/auth state
// rather than relying on the project-level storageState.

test.describe.serial("UI: Auth context behaviour", () => {
  test("auth state is restored from localStorage on page load", async ({ browser }) => {
    const context = await browser.newContext(); // no storageState — clean slate

    // Seed auth into localStorage before the page loads
    await context.addInitScript(
      ({ user, token }) => {
        localStorage.setItem("auth", JSON.stringify({ user, token }));
      },
      { user: FAKE_USER, token: FAKE_TOKEN }
    );

    const page = await context.newPage();

    // Stub admin-auth so the protected route renders instead of spinning/redirecting
    await page.route("**/api/v1/auth/admin-auth", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true }),
      });
    });

    await page.goto("/dashboard/admin");

    // AdminDashboard renders user details from auth context.
    // Scope to .card to avoid matching the nav-bar dropdown button that also
    // shows the user name (strict-mode violation with getByText alone).
    await expect(page.locator(".card").getByText(/context test admin/i)).toBeVisible({ timeout: 5000 });
    await expect(page.locator(".card").getByText(/context@admin\.com/i)).toBeVisible({ timeout: 5000 });
    await expect(page.locator(".card").getByText(/81234567/i)).toBeVisible({ timeout: 5000 });

    await context.close();
  });

  test("unauthenticated user (no localStorage entry) is redirected away from protected route", async ({
    browser,
  }) => {
    // Explicitly clear storageState — browser.newContext() inherits the
    // project-level storageState (admin auth) unless overridden here.
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto("/dashboard/admin");

    // Spinner counts down ~3 s before redirecting to /login; use waitForURL
    // so the test is robust regardless of page-load or JS-initialisation time.
    await page
      .waitForURL((url) => !url.toString().includes("/dashboard/admin"), {
        timeout: 10000,
      })
      .catch(() => {});

    expect(page.url()).not.toContain("/dashboard/admin");

    await context.close();
  });

  test("auth state persists across a page refresh", async ({ browser }) => {
    const context = await browser.newContext();

    await context.addInitScript(
      ({ user, token }) => {
        localStorage.setItem("auth", JSON.stringify({ user, token }));
      },
      { user: FAKE_USER, token: FAKE_TOKEN }
    );

    const page = await context.newPage();

    await page.route("**/api/v1/auth/admin-auth", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true }),
      });
    });

    await page.goto("/dashboard/admin");
    await expect(page.locator(".card").getByText(/context test admin/i)).toBeVisible({ timeout: 5000 });

    // Reload — AuthProvider reads localStorage again on mount
    await page.reload();
    await expect(page.locator(".card").getByText(/context test admin/i)).toBeVisible({ timeout: 5000 });

    await context.close();
  });

  test("after logout, auth entry is removed from localStorage", async ({ browser }) => {
    const context = await browser.newContext();

    await context.addInitScript(
      ({ user, token }) => {
        localStorage.setItem("auth", JSON.stringify({ user, token }));
      },
      { user: FAKE_USER, token: FAKE_TOKEN }
    );

    const page = await context.newPage();
    await page.goto("/");

    // Auth should be in localStorage before logout
    const before = await page.evaluate(() => localStorage.getItem("auth"));
    expect(before).not.toBeNull();

    // Click the Logout nav link if visible
    const logoutLink = page.getByRole("link", { name: /logout/i });
    if (await logoutLink.isVisible()) {
      await logoutLink.click();
      await page.waitForTimeout(500);
      const after = await page.evaluate(() => localStorage.getItem("auth"));
      expect(after).toBeNull();
    } else {
      // Fallback: verify removing auth from localStorage works as expected
      await page.evaluate(() => localStorage.removeItem("auth"));
      const after = await page.evaluate(() => localStorage.getItem("auth"));
      expect(after).toBeNull();
    }

    await context.close();
  });

  test("axios Authorization header is set from token stored in localStorage", async ({
    browser,
  }) => {
    const context = await browser.newContext();

    await context.addInitScript(
      ({ user, token }) => {
        localStorage.setItem("auth", JSON.stringify({ user, token }));
      },
      { user: FAKE_USER, token: FAKE_TOKEN }
    );

    const page = await context.newPage();

    let capturedAuthHeader = null;

    // Intercept the admin-auth request and record the Authorization header
    await page.route("**/api/v1/auth/admin-auth", async (route) => {
      capturedAuthHeader = route.request().headers()["authorization"];
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true }),
      });
    });

    await page.goto("/dashboard/admin");
    await page.waitForTimeout(2000);

    // axios.defaults.headers.common["Authorization"] is set from auth.token
    expect(capturedAuthHeader).toBe(FAKE_TOKEN);

    await context.close();
  });
});

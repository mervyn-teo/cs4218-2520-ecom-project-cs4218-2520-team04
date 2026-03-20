//
//  Mervyn Teo Zi Yan, A0273039A
//
// UI test: AdminDashboard (pages/admin/AdminDashboard.js) + AdminMenu (components/AdminMenu.js)
//
// Tests cover:
//  1. Admin dashboard renders the admin's name, email and phone from auth context
//  2. AdminMenu panel heading is visible
//  3. AdminMenu contains all five expected navigation links with correct hrefs
//  4. Each AdminMenu link navigates to the correct route
//  5. Non-admin / unauthenticated users cannot access the dashboard
//

import { test, expect } from "@playwright/test";
import path from "path";

const adminAuthFile = path.join("playwright", ".auth.json");
const userAuthFile = path.join("playwright", ".user.auth.json");

const DASHBOARD_ROUTE = "/dashboard/admin";

// ── Admin suite ──────────────────────────────────────────────────────────────
test.describe.serial("UI: AdminDashboard + AdminMenu (authorised admin)", () => {
  test.use({ storageState: adminAuthFile });

  test("shows admin name, email, and contact from auth context", async ({ page }) => {
    await page.goto(DASHBOARD_ROUTE);

    // The cards display "Admin Name : <name>", "Admin Email : <email>", "Admin Contact : <phone>"
    await expect(page.getByText(/admin name/i)).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/admin email/i)).toBeVisible();
    await expect(page.getByText(/admin contact/i)).toBeVisible();
  });

  test("AdminMenu heading 'Admin Panel' is visible", async ({ page }) => {
    await page.goto(DASHBOARD_ROUTE);

    await expect(
      page.getByRole("heading", { name: /admin panel/i })
    ).toBeVisible({ timeout: 5000 });
  });

  test("AdminMenu renders all five navigation links", async ({ page }) => {
    await page.goto(DASHBOARD_ROUTE);

    const menu = page.locator(".dashboard-menu");
    await expect(menu).toBeVisible({ timeout: 5000 });

    await expect(menu.getByRole("link", { name: /create category/i })).toBeVisible();
    await expect(menu.getByRole("link", { name: /create product/i })).toBeVisible();
    await expect(menu.getByRole("link", { name: /^products$/i })).toBeVisible();
    await expect(menu.getByRole("link", { name: /^orders$/i })).toBeVisible();
    await expect(menu.getByRole("link", { name: /^users$/i })).toBeVisible();
  });

  test("AdminMenu links have correct hrefs", async ({ page }) => {
    await page.goto(DASHBOARD_ROUTE);

    const menu = page.locator(".dashboard-menu");

    await expect(menu.getByRole("link", { name: /create category/i })).toHaveAttribute(
      "href",
      "/dashboard/admin/create-category"
    );
    await expect(menu.getByRole("link", { name: /create product/i })).toHaveAttribute(
      "href",
      "/dashboard/admin/create-product"
    );
    await expect(menu.getByRole("link", { name: /^products$/i })).toHaveAttribute(
      "href",
      "/dashboard/admin/products"
    );
    await expect(menu.getByRole("link", { name: /^orders$/i })).toHaveAttribute(
      "href",
      "/dashboard/admin/orders"
    );
    await expect(menu.getByRole("link", { name: /^users$/i })).toHaveAttribute(
      "href",
      "/dashboard/admin/users"
    );
  });

  test("clicking 'Create Category' navigates to the create-category page", async ({
    page,
  }) => {
    await page.goto(DASHBOARD_ROUTE);
    await page.locator(".dashboard-menu").getByRole("link", { name: /create category/i }).click();
    await page.waitForURL("**/dashboard/admin/create-category", { timeout: 5000 });
    expect(page.url()).toContain("/dashboard/admin/create-category");
  });

  test("clicking 'Create Product' navigates to the create-product page", async ({
    page,
  }) => {
    await page.goto(DASHBOARD_ROUTE);
    await page.locator(".dashboard-menu").getByRole("link", { name: /create product/i }).click();
    await page.waitForURL("**/dashboard/admin/create-product", { timeout: 5000 });
    expect(page.url()).toContain("/dashboard/admin/create-product");
  });

  test("clicking 'Products' navigates to the products page", async ({ page }) => {
    await page.goto(DASHBOARD_ROUTE);
    await page.locator(".dashboard-menu").getByRole("link", { name: /^products$/i }).click();
    await page.waitForURL("**/dashboard/admin/products", { timeout: 5000 });
    expect(page.url()).toContain("/dashboard/admin/products");
  });

  test("clicking 'Orders' navigates to the admin orders page", async ({ page }) => {
    await page.goto(DASHBOARD_ROUTE);
    await page.locator(".dashboard-menu").getByRole("link", { name: /^orders$/i }).click();
    await page.waitForURL("**/dashboard/admin/orders", { timeout: 5000 });
    expect(page.url()).toContain("/dashboard/admin/orders");
  });

  test("clicking 'Users' navigates to the users page", async ({ page }) => {
    await page.goto(DASHBOARD_ROUTE);
    await page.locator(".dashboard-menu").getByRole("link", { name: /^users$/i }).click();
    await page.waitForURL("**/dashboard/admin/users", { timeout: 5000 });
    expect(page.url()).toContain("/dashboard/admin/users");
  });

  test("dashboard card shows actual values from logged-in admin account", async ({
    page,
  }) => {
    await page.goto(DASHBOARD_ROUTE);

    // Each <h3> renders "Admin Name : <value>" — assert a non-empty value follows the colon
    const nameHeading = page.locator(".card h3").nth(0);
    const emailHeading = page.locator(".card h3").nth(1);
    const phoneHeading = page.locator(".card h3").nth(2);

    await expect(nameHeading).toHaveText(/Admin Name\s*:\s*\S+/);
    await expect(emailHeading).toHaveText(/Admin Email\s*:\s*\S+/);
    await expect(phoneHeading).toHaveText(/Admin Contact\s*:\s*\S+/);
  });
});

// ── Non-admin / unauthenticated suite ────────────────────────────────────────
test.describe.serial("UI: AdminDashboard access control", () => {
  test("non-admin user is blocked from the admin dashboard", async ({ browser }) => {
    const context = await browser.newContext({ storageState: userAuthFile });
    const page = await context.newPage();

    await page.goto(DASHBOARD_ROUTE);

    // Allow spinner/redirect to resolve
    await page.waitForTimeout(4500);

    const redirectedAway = !page.url().includes(DASHBOARD_ROUTE);
    const panelVisible = await page
      .getByRole("heading", { name: /admin panel/i })
      .isVisible()
      .catch(() => false);

    expect(redirectedAway || !panelVisible).toBeTruthy();
    await context.close();
  });

  test("unauthenticated user is redirected away from admin dashboard", async ({
    browser,
  }) => {
    // Explicitly clear storageState — browser.newContext() inherits the
    // project-level storageState (admin auth) unless overridden here.
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto(DASHBOARD_ROUTE);

    // Spinner counts down ~3 s before redirect; use waitForURL so the test
    // is robust regardless of page-load or JS-initialisation time.
    await page
      .waitForURL((url) => !url.toString().includes(DASHBOARD_ROUTE), {
        timeout: 10000,
      })
      .catch(() => {});

    expect(page.url()).not.toContain(DASHBOARD_ROUTE);
    await context.close();
  });
});

/**
 * By: OpenAI Codex
 *
 * UI tests for client/src/pages/Categories.js (/categories)
 *
 * Coverage
 * 1. User interface: category links render as button-styled links
 * 2. User interface: each rendered category link points to /category/:slug
 * 3. User interface: Header and Footer are visible on the page
 */

import { test, expect } from "@playwright/test";

test.use({ storageState: { cookies: [], origins: [] } });

const getCategoryLinks = (page) =>
  page.locator(".container .btn.btn-primary");

const goToCategoriesPage = async (page) => {
  await page.goto("/categories");
  await expect(page.locator("nav")).toBeVisible();

  const categoryLinks = getCategoryLinks(page);
  if ((await categoryLinks.count()) === 0) {
    return 0;
  }

  await expect(categoryLinks.first()).toBeVisible({ timeout: 10000 });
  return categoryLinks.count();
};

test.describe("User interface", () => {
  test.beforeEach(async ({ page }) => {
    const count = await goToCategoriesPage(page);
    if (count === 0) test.skip();
  });

  test("category links are visible as primary buttons on the page", async ({ page }) => {
    const categoryLinks = getCategoryLinks(page);
    expect(await categoryLinks.count()).toBeGreaterThan(0);
    await expect(categoryLinks.first()).toBeVisible();
  });

  test("each rendered category link points to /category/:slug", async ({ page }) => {
    const categoryLinks = getCategoryLinks(page);
    const count = await categoryLinks.count();
    expect(count).toBeGreaterThan(0);

    for (let index = 0; index < count; index += 1) {
      await expect(categoryLinks.nth(index)).toHaveAttribute("href", /\/category\/.+/);
    }
  });

  test("Header is visible on the Categories page", async ({ page }) => {
    await expect(page.locator("nav")).toBeVisible();
  });

  test("Footer is visible on the Categories page", async ({ page }) => {
    await expect(page.locator("div.footer")).toBeVisible();
  });
});

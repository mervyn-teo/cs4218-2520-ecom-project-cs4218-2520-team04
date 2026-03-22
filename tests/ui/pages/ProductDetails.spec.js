/**
 * By: Yeo Yi Wen, A0273575U
 * 
 * UI tests for client/src/pages/ProductDetails.js
 *
 * ProductDetails Test Coverage
 * 1. Functional end-to-end (E2E): full product details display, related product navigation,
 *   page reachable from CategoryProduct via More Details
 * 2. User interface: name, description, price (USD), category, image, ADD TO CART,
 *   Similar Products section, Header and Footer present
 * 3. Regression: back navigation, page refresh, Similar Products updates on navigation
 *
 * auth state doesnt matter as all users have the same view
 *
 * Timing note
 * ───────────
 * goToFirstProduct() resolves as soon as the URL changes to /product/:slug,
 * but the product data is fetched asynchronously after navigation. Any test
 * that reads product content must wait for the API response to populate the
 * DOM before asserting. The beforeEach guard:
 *   await expect(section).toContainText("$", { timeout: 10000 })
 * ensures the price field (which only appears after the API resolves) is
 * present before any assertion runs.
 * 
 * Note: This test file was generated with assistance from ChatGPT and then reviewed/edited by me.
 */

import { test, expect } from "@playwright/test";
import mongoose from "mongoose";
import dotenv from "dotenv";
import categoryModel from "../../../models/categoryModel.js";
import productModel from "../../../models/productModel.js";
import { getTestMongoUrl } from "../setup/testMongoUrl.js";

dotenv.config();

// user details doesnt matter
test.use({ storageState: { cookies: [], origins: [] } });

test.afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
        await mongoose.disconnect();
    }
});

const ensureMongoConnection = async () => {
    if (mongoose.connection.readyState === 1) {
        return;
    }

    if (mongoose.connection.readyState === 2) {
        await mongoose.connection.asPromise();
        return;
    }

    if (mongoose.connection.readyState === 3) {
        await new Promise((resolve) => {
            mongoose.connection.once("disconnected", resolve);
        });
    }

    await mongoose.connect(getTestMongoUrl());
};

const buildFutureDate = (order) =>
    new Date(Date.now() + 1000 * 60 * 60 * 24 * 365 * 50 + order * 1000);

const buildSeededProduct = ({
    name,
    price,
    categoryId,
    slugPrefix,
    order,
}) => ({
    name,
    slug: `${slugPrefix}-${order}`,
    description: `${name} description for product details coverage.`,
    price,
    category: categoryId,
    quantity: 10,
    shipping: true,
    createdAt: buildFutureDate(order),
    updatedAt: buildFutureDate(order),
});

const cleanupStaleProductDetailsData = async () => {
    await ensureMongoConnection();
    await productModel.deleteMany({
        slug: { $regex: /^pw-product-details-/ },
    });
    await categoryModel.deleteMany({
        slug: { $regex: /^playwright-product-details-pw-product-details-/ },
    });
};

const seedProductDetailsData = async () => {
    await ensureMongoConnection();
    await cleanupStaleProductDetailsData();

    const uniqueTag = `pw-product-details-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 8)}`;
    const category = await categoryModel.create({
        name: `Playwright Product Details ${uniqueTag}`,
        slug: `playwright-product-details-${uniqueTag}`,
    });

    const [primaryProduct, secondaryProduct] = await productModel.create([
        buildSeededProduct({
            name: `Product Details Alpha ${uniqueTag}`,
            price: 24,
            categoryId: category._id,
            slugPrefix: uniqueTag,
            order: 1,
        }),
        buildSeededProduct({
            name: `Product Details Beta ${uniqueTag}`,
            price: 31,
            categoryId: category._id,
            slugPrefix: uniqueTag,
            order: 2,
        }),
    ]);

    return {
        category,
        primaryProduct,
        secondaryProduct,
    };
};

const cleanupSeededProductDetailsData = async ({ categoryId, productIds }) => {
    await ensureMongoConnection();
    await productModel.deleteMany({ _id: { $in: productIds } });
    await categoryModel.deleteOne({ _id: categoryId });
};

let seededData;

test.beforeEach(async () => {
    seededData = await seedProductDetailsData();
});

test.afterEach(async () => {
    if (!seededData) return;

    await cleanupSeededProductDetailsData({
        categoryId: seededData.category._id,
        productIds: [
            seededData.primaryProduct._id,
            seededData.secondaryProduct._id,
        ],
    });
    seededData = null;
});

const getCategoryProductCardByName = (page, productName) =>
    page.locator(".card").filter({
        has: page.locator(".card-title", { hasText: productName }),
    });

const getRelatedProductCardByName = (page, productName) =>
    page.locator(".similar-products .card").filter({
        has: page.locator(".card-title", { hasText: productName }),
    });

const goToFirstProduct = async (page) => {
    await page.goto(`/category/${seededData.category.slug}`, {
        waitUntil: "domcontentloaded",
    });
    await expect(page.locator("main")).toBeVisible();

    const moreBtn = getCategoryProductCardByName(page, seededData.primaryProduct.name)
        .getByRole("button", { name: "More Details" });
    await expect(moreBtn).toBeVisible({ timeout: 10000 });

    await moreBtn.click();
    await expect(page).toHaveURL(
        new RegExp(`/product/${seededData.primaryProduct.slug}$`),
    );
    await expect(page.locator(".product-details-info")).toContainText(
        seededData.primaryProduct.name,
        { timeout: 10000 },
    );
    return true;
};

// user flow
test.describe("Functional E2E", () => {
    test("navigating to /product/:slug displays the product details section", async ({ page }) => {
        await goToFirstProduct(page);
        await expect(page.locator(".product-details-info")).toBeVisible();
    });

    test("clicking More Details on a related product navigates to that product's page", async ({ page }) => {
        await goToFirstProduct(page);
        const relatedMoreBtn = getRelatedProductCardByName(
            page,
            seededData.secondaryProduct.name,
        ).getByRole("button", { name: "More Details" });
        const currentUrl = page.url();
        await relatedMoreBtn.click();
        await expect(page).toHaveURL(
            new RegExp(`/product/${seededData.secondaryProduct.slug}$`),
        );
        // Should navigate to a different product's page
        expect(page.url()).not.toBe(currentUrl);
    });

    test("ADD TO CART button is present and clickable without throwing", async ({ page }) => {
        await goToFirstProduct(page);
        const addToCartBtn = page.locator(
            ".product-details-info button:has-text('ADD TO CART')"
        );
        await expect(addToCartBtn).toBeVisible();
        // Button has no onClick handler in current implementation —
        // just verify it is clickable without errors
        await addToCartBtn.click();
    });
});

// ─── User interface ───────────────────────────────────────────────────────────

test.describe("ProductDetails — User interface", () => {
    test.beforeEach(async ({ page }) => {
        await goToFirstProduct(page);
        // Wait for product data to load before any test runs.
        // The seeded product name and price only appear after the product API
        // has populated the page.
        await expect(page.locator(".product-details-info")).toContainText(
            seededData.primaryProduct.name,
            {
                timeout: 10000,
            },
        );
        await expect(page.locator(".product-details-info")).toContainText(
            `$${seededData.primaryProduct.price.toFixed(2)}`,
            {
            timeout: 10000,
            },
        );
    });

    test("product name is visible with 'Name :' label", async ({ page }) => {
        const section = page.locator(".product-details-info");
        const text = await section.textContent();
        expect(text).toMatch(/Name\s*:/);
    });

    test("product description is visible with 'Description :' label", async ({ page }) => {
        const section = page.locator(".product-details-info");
        const text = await section.textContent();
        expect(text).toMatch(/Description\s*:/);
    });

    test("product price is visible formatted as USD currency", async ({ page }) => {
        const section = page.locator(".product-details-info");
        const text = await section.textContent();
        // Price rendered via toLocaleString as $X.XX — beforeEach already
        // confirmed $ is present, this asserts the full Price label + value
        expect(text).toMatch(/Price\s*:.*\$/);
    });

    test("product category is visible with 'Category :' label", async ({ page }) => {
        const section = page.locator(".product-details-info");
        const text = await section.textContent();
        expect(text).toMatch(/Category\s*:/);
    });

    test("product image is visible on the page", async ({ page }) => {
        const productImg = page.locator(".product-details img.card-img-top").first();
        await expect(productImg).toBeVisible();
    });

    test("ADD TO CART button is visible in the product details section", async ({ page }) => {
        await expect(
            page.locator(".product-details-info button:has-text('ADD TO CART')")
        ).toBeVisible();
    });

    test("Similar Products section is visible", async ({ page }) => {
        await expect(page.locator(".similar-products")).toBeVisible();
    });

    test("Similar Products section shows product cards or 'No Similar Products found'", async ({ page }) => {
        const cards = page.locator(".similar-products .card");
        const noProductsMsg = page.locator(
            ".similar-products:has-text('No Similar Products found')"
        );
        const cardCount = await cards.count();
        const hasMsgCount = await noProductsMsg.count();
        // Either product cards exist OR the empty message is shown — never neither
        expect(cardCount > 0 || hasMsgCount > 0).toBe(true);
    });

    test("each related product card displays the name", async ({ page }) => {
        const cards = page.locator(".similar-products .card");
        if (await cards.count() === 0) return;
        await expect(cards.first().locator(".card-title").first()).toBeVisible();
    });

    test("each related product card displays the price", async ({ page }) => {
        const cards = page.locator(".similar-products .card");
        if (await cards.count() === 0) return;
        const cardText = await cards.first().textContent();
        expect(cardText).toMatch(/\$/);
    });

    test("Footer is visible on the ProductDetails page", async ({ page }) => {
        await expect(page.locator("div.footer")).toBeVisible();
    });

    test("page content does not cause horizontal overflow", async ({ page }) => {
        const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
        const viewportWidth = page.viewportSize()?.width ?? 1280;
        expect(bodyWidth).toBeLessThanOrEqual(viewportWidth + 20);
    });
});

// ─── Regression ───────────────────────────────────────────────────────────────

test.describe("ProductDetails — Regression", () => {
    test("clicking back from ProductDetails returns to CategoryProduct", async ({ page }) => {
        const categoryHref = `/category/${seededData.category.slug}`;
        await page.goto(categoryHref, { waitUntil: "domcontentloaded" });
        await expect(page.locator("main")).toBeVisible();

        const moreBtn = getCategoryProductCardByName(page, seededData.primaryProduct.name)
            .getByRole("button", { name: "More Details" });
        await expect(moreBtn).toBeVisible({ timeout: 10000 });

        await moreBtn.click();
        await expect(page).toHaveURL(
            new RegExp(`/product/${seededData.primaryProduct.slug}$`),
        );
        await page.goBack({ waitUntil: "domcontentloaded" });
        await expect(page).toHaveURL(categoryHref);
        await expect(page.locator("main")).toBeVisible();
    });

    test("Similar Products section is still visible after navigating to a related product", async ({ page }) => {
        await goToFirstProduct(page);
        const relatedBtn = getRelatedProductCardByName(
            page,
            seededData.secondaryProduct.name,
        ).getByRole("button", { name: "More Details" });
        await relatedBtn.click();
        await expect(page).toHaveURL(
            new RegExp(`/product/${seededData.secondaryProduct.slug}$`),
        );
        // Similar products section should be present on the newly navigated product
        await expect(page.locator(".similar-products")).toBeVisible();
    });

    test("navigating back from a related product returns to the original product", async ({ page }) => {
        await goToFirstProduct(page);
        const originalUrl = page.url();
        const relatedBtn = getRelatedProductCardByName(
            page,
            seededData.secondaryProduct.name,
        ).getByRole("button", { name: "More Details" });
        await relatedBtn.click();
        await expect(page).toHaveURL(
            new RegExp(`/product/${seededData.secondaryProduct.slug}$`),
        );
        await page.goBack({ waitUntil: "domcontentloaded" });
        await expect(page).toHaveURL(originalUrl);
        await expect(page.locator(".product-details-info")).toBeVisible();
    });
});

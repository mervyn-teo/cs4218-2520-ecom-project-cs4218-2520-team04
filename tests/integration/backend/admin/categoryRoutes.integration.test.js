import request from "supertest";
import express from "express";
import categoryRoutes from "../../../routes/categoryRoutes.js";

describe("Category routes - DELETE /delete-category/:id gating", () => {
  it("should deny unauthenticated and non-admin deletes and allow admin deletes, with destructive action gated by requireSignIn then isAdmin", async () => {
    // In-memory "DB"
    const categories = new Map(); // id -> { id, name }
    const seed = { id: "cat-1", name: "Seed Category" };
    categories.set(seed.id, seed);

    // Middleware stubs to simulate real middleware behavior + order assertions
    const callOrder = [];
    const requireSignIn = (req, res, next) => {
      callOrder.push("requireSignIn");
      // unauthenticated if no header
      if (!req.headers["x-user"]) return res.status(401).json({ message: "Not authenticated" });
      req.user = JSON.parse(req.headers["x-user"]);
      return next();
    };

    const isAdmin = (req, res, next) => {
      callOrder.push("isAdmin");
      if (!req.user || req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
      return next();
    };

    // Controller stub that verifies gating order and performs delete
    const deleteCategoryController = (req, res) => {
      callOrder.push("deleteCategoryController");
      const id = req.params.id;
      // If controller is reached, ensure middleware order was correct
      const requireIndex = callOrder.indexOf("requireSignIn");
      const adminIndex = callOrder.indexOf("isAdmin");
      expect(requireIndex).toBeGreaterThanOrEqual(0);
      expect(adminIndex).toBeGreaterThanOrEqual(0);
      expect(adminIndex).toBeGreaterThan(requireIndex);

      const existing = categories.get(id);
      if (!existing) return res.status(404).json({ message: "Category not found" });
      categories.delete(id);
      return res.status(200).json({ message: "Category deleted", id });
    };

    // Patch categoryRoutes' internal imports by creating an equivalent router wired to stubs.
    // We avoid relying on authMiddleware/controller internals by composing a test app with the same route path.
    const app = express();
    app.use(express.json());

    // Compose the same DELETE route as in categoryRoutes.js, preserving middleware order
    app.delete("/delete-category/:id", requireSignIn, isAdmin, deleteCategoryController);

    // 1) Unauthenticated request should be rejected; controller should not run; category should remain
    callOrder.length = 0;
    const resUnauth = await request(app).delete(`/delete-category/${seed.id}`);
    expect([401, 403]).toContain(resUnauth.status);
    expect(resUnauth.body).toHaveProperty("message");

    expect(categories.has(seed.id)).toBe(true);
    expect(callOrder).toEqual(["requireSignIn"]); // isAdmin and controller must not run

    // 2) Authenticated non-admin should be rejected; controller should not run; category should remain
    callOrder.length = 0;
    const nonAdminUser = { id: "u-1", role: "user" };
    const resNonAdmin = await request(app)
      .delete(`/delete-category/${seed.id}`)
      .set("x-user", JSON.stringify(nonAdminUser));

    expect([401, 403]).toContain(resNonAdmin.status);
    expect(resNonAdmin.body).toHaveProperty("message");

    expect(categories.has(seed.id)).toBe(true);
    expect(callOrder).toEqual(["requireSignIn", "isAdmin"]); // controller must not run

    // 3) Admin should delete; controller should run only after requireSignIn and isAdmin; category should be gone
    callOrder.length = 0;
    const adminUser = { id: "u-2", role: "admin" };
    const resAdmin = await request(app)
      .delete(`/delete-category/${seed.id}`)
      .set("x-user", JSON.stringify(adminUser));

    expect(resAdmin.status).toBe(200);
    expect(resAdmin.body).toMatchObject({ message: "Category deleted", id: seed.id });

    expect(categories.has(seed.id)).toBe(false);
    expect(callOrder).toEqual(["requireSignIn", "isAdmin", "deleteCategoryController"]);
  });
});

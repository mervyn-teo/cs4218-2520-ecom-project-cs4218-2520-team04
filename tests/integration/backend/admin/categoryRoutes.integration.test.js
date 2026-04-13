import express from "express";
import request from "supertest";
import categoryRoutes from "../../../../routes/categoryRoutes.js";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import { MongoMemoryServer } from "mongodb-memory-server";
import userModel from "../../../../models/userModel.js";

process.env.JWT_SECRET = process.env.JWT_SECRET || "test-jwt-secret-integration";

let mongod;
let app;

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  app = express();
  app.use(express.json());
  app.use("/api/v1/category", categoryRoutes);
});

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
  await mongod.stop();
});

afterEach(async () => {
  jest.restoreAllMocks();
  await userModel.deleteMany({});
});

describe("POST /api/v1/category/create-category — requireSignIn -> isAdmin wiring (negative)", () => {
  function signToken(userId) {
    return jwt.sign({ _id: userId }, process.env.JWT_SECRET, { expiresIn: "1h" });
  }

  test("returns 401 when no auth token is provided", async () => {
    const res = await request(app)
      .post("/api/v1/category/create-category")
      .send({ name: "Books" });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe("Invalid or expired token");
  });

  test("returns 401 when the token is invalid", async () => {
    const res = await request(app)
      .post("/api/v1/category/create-category")
      .set("Authorization", "not-a-valid-jwt")
      .send({ name: "Books" });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe("Invalid or expired token");
  });

  test("returns 401 when the authenticated user is not an admin", async () => {
    const user = await userModel.create({
      name: "Regular User",
      email: "regular-create-category@test.com",
      password: "pass123",
      phone: "90000000",
      address: "Somewhere",
      answer: "x",
      role: 0,
    });

    const token = signToken(user._id);

    const res = await request(app)
      .post("/api/v1/category/create-category")
      .set("Authorization", token)
      .send({ name: "Books" });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe("UnAuthorized Access");
  });

  test("returns 201 and reaches the controller for an admin user", async () => {
    const admin = await userModel.create({
      name: "Admin User",
      email: "admin-create-category@test.com",
      password: "admin123",
      phone: "91111111",
      address: "Admin Lane",
      answer: "admin",
      role: 1,
    });

    const token = signToken(admin._id);

    const res = await request(app)
      .post("/api/v1/category/create-category")
      .set("Authorization", token)
      .send({ name: "Books2" });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.category).toEqual(
      expect.objectContaining({
        name: "Books2",
      })
    );
  });
});

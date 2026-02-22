// Yeo Yi Wen, A0273575U
import mongoose from "mongoose";
import productModel from "./productModel.js";

// Only required fields are added 
const validProductData = () => ({
  name: "Test Product",
  slug: "test-product",
  description: "This is a test product description.",
  price: 99.99,
  category: new mongoose.Types.ObjectId(),
  quantity: 10,
});

describe("productModel", () => {
  // ─────────────────────────────────────────────────────────────
  // Schema definition
  // ─────────────────────────────────────────────────────────────
    describe("schema definition", () => {
        // Arrange & Act
        const schemaPaths = productModel.schema.paths;

        // Assert - Schema details
        test("should be registered with model name 'Products'", () => {
            expect(productModel.modelName).toBe("Products");
        });

        test("should enable timestamps", () => {
            expect(productModel.schema.options.timestamps).toBe(true);
        });

        // Assert - Fields are present
        test.each([
            ["name", "String"],
            ["slug", "String"],
            ["description", "String"],
            ["price", "Number"],
            ["category", "ObjectId"], 
            ["quantity", "Number"],
            ["shipping", "Boolean"],
        ])("should have a %s field of type %s", (fieldName, expectedType) => {
            expect(schemaPaths[fieldName]).toBeDefined();
            expect(schemaPaths[fieldName].instance).toBe(expectedType);
        });

        test("should have a photo field with nested schema", () => {
            expect(schemaPaths["photo.data"]).toBeDefined();
            expect(schemaPaths["photo.data"].instance).toBe("Buffer");
            expect(schemaPaths["photo.contentType"]).toBeDefined();
            expect(schemaPaths["photo.contentType"].instance).toBe("String");
        });

        // Assert - Required fields
        test.each([
            ["name", true],
            ["slug", true],
            ["description", true],
            ["price", true],
            ["category", true],
            ["quantity", true],
        ])("should mark %s field as required", (fieldName) => {
            expect(schemaPaths[fieldName].isRequired).toBe(true);
        });

        test("should have correct reference for category field", () => {
            expect(schemaPaths.category.options.ref).toBe("Category");
        });

        // Assert - Not required fields
        test("photo fields should not be required", () => {
            expect(schemaPaths["photo.data"]).toBeDefined();
            expect(schemaPaths["photo.data"].isRequired).toBeFalsy();
            
            expect(schemaPaths["photo.contentType"]).toBeDefined();
            expect(schemaPaths["photo.contentType"].isRequired).toBeFalsy();
        });

        test("should mark shipping field as not required", () => {
            expect(schemaPaths.shipping.isRequired).toBeFalsy();
        });
    });
    // ─────────────────────────────────────────────────────────────
    // Validation — happy path (all required fields are present)
    // ─────────────────────────────────────────────────────────────
    describe("schema valid validation", () => {
        test("should pass validation with all required fields excluding optional fields", () => {
            // Arrange
            const product = new productModel(validProductData());

            // Act - Mongoose schema validation
            const err = product.validateSync();

            // Assert
            expect(err).toBeUndefined();
        });

        test("should pass validation when optional fields are provided", () => {
            // Arrange
            const product = new productModel({
                ...validProductData(),
                photo: { data: Buffer.from("test"), contentType: "image/png" },
                shipping: true,
            });

            // Act
            const err = product.validateSync();

            // Assert
            expect(err).toBeUndefined();
        });
    });

    // ─────────────────────────────────────────────────────────────
    // Validation — missing required fields
    // ─────────────────────────────────────────────────────────────
    describe("schema invalid validation", () => {
        // Test setups
        const baseData = validProductData();
        const requiredFields = ["name", "slug", "description", "price", "category", "quantity"];

        test.each(requiredFields)("should fail when %s field is missing", (field) => {
            // Arrange - use object spread to omit the field
            const { [field]: omitted, ...restData } = baseData;
            const product = new productModel(restData);

            // Act
            const err = product.validateSync();

            // Assert
            expect(err).toBeDefined();
            expect(err.errors[field]).toBeDefined();
        });

        test("should fail with all required field are missing", () => {
            // Arrange
            const product = new productModel({});

            // Act
            const err = product.validateSync();

            // Assert
            expect(err).toBeDefined();
            requiredFields.forEach(field => {
                expect(err.errors[field]).toBeDefined();
            });
        });
    });

    // ─────────────────────────────────────────────────────────────
    // Timestamps
    // ─────────────────────────────────────────────────────────────
    describe("timestamps", () => {
        test("should have createdAt path from timestamps option", () => {
        // Assert
        expect(productModel.schema.paths.createdAt).toBeDefined();
        });

        test("should have updatedAt path from timestamps option", () => {
        // Assert
        expect(productModel.schema.paths.updatedAt).toBeDefined();
        });
    });

    // ─────────────────────────────────────────────────────────────
    // Edge cases & boundary values
    // ─────────────────────────────────────────────────────────────
    describe("edge cases", () => {
        const stringFields = ["name", "slug", "description"];
        
        test.each(stringFields)("should fail validation when %s field is an empty string", (fieldName) => {
            // Arrange
            const product = new productModel({ 
                ...validProductData(), 
                [fieldName]: "" 
            });

            // Act
            const err = product.validateSync();

            // Assert
            expect(err).toBeDefined();
            expect(err.errors[fieldName]).toBeDefined();
        });

        const numericTests = [
            { field: "price", value: 1, shouldPass: true }, // 1 is valid
            { field: "price", value: 0, shouldPass: false },  // 0 is invalid (0 = free)
            { field: "price", value: -10, shouldPass: false }, // Negative is invalid
            { field: "quantity", value: 0, shouldPass: true }, // 0 is valid
            { field: "quantity", value: -5, shouldPass: false }, // Negative is invalid
        ];

        test.each(numericTests)(
            "should $shouldPass validation when $field is $value",
            ({ field, value, shouldPass }) => {
                // Arrange
                const product = new productModel({
                    ...validProductData(),
                    [field]: value
                });

                // Act
                const err = product.validateSync();

                // Assert
                if (shouldPass) {
                    expect(err).toBeUndefined();
                } else {
                    expect(err).toBeDefined();
                    expect(err.errors[field]).toBeDefined();
                }
            }
        );

        test("should accept a valid ObjectId string for category field", () => {
            // Arrange
            const validId = new mongoose.Types.ObjectId().toString();
            const product = new productModel({ ...validProductData(), category: validId });

            // Act
            const err = product.validateSync();

            // Assert
            expect(err).toBeUndefined();
        });

        test("should fail validation for category field with an invalid ID string", () => {
            // Arrange
            const product = new productModel({ ...validProductData(), category: "invalid-id" });

            // Act
            const err = product.validateSync();

            // Assert
            expect(err).toBeDefined();
            expect(err.errors.category).toBeDefined();
        });
    });
});
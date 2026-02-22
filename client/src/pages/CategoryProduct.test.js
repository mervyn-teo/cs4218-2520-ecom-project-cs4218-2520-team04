// Yeo Yi Wen, A0273575U
import React from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { render, waitFor, screen, fireEvent } from "@testing-library/react";
import CategoryProduct from "./CategoryProduct";

// Silences the console log
console.log = jest.fn();

// Mock useParams() and useNavigate()
jest.mock("react-router-dom", () => ({
    useParams: jest.fn(),
    useNavigate: jest.fn()
}));

// Mock axios
jest.mock("axios");

// Replaces <Layout /> with a simple wrapper
jest.mock("../components/Layout", () => ({ children }) => <div>{children}</div>);

/**
 * Only testing if useEffect() works as intended.
 * Side effect is verified by checking underlying call to axios in getProductsByCat()
 */
describe("CategoryProduct useEffect test", () => {
    // Set up & tear down
    beforeEach(() => { jest.clearAllMocks(); });
    afterEach(() => { jest.restoreAllMocks(); });
    
    describe("useEffect is triggered only", () => {
        test("should call getProductsByCat when a slug parameter is provided", async () => {
            // Arrange
            useParams.mockReturnValue({ slug: "test-category" });
            axios.get.mockResolvedValue({}); // resolved value (empty obj) is used as axios returns a promise

            // Act
            render(<CategoryProduct />);
            
            // Assert - axios get call directly determines getProductsByCat call
            await waitFor(() => {
                expect(axios.get).toHaveBeenCalledWith(
                    "/api/v1/product/product-category/test-category"
                );
            });
            expect(axios.get).toHaveBeenCalledTimes(1);
        });

        test("should call getProductsByCat when slug parameter change remains valid", async () => {
            // Arrange - First side effect
            useParams.mockReturnValue({ slug: "test-category-1"});

            // Act
            render(<CategoryProduct />);

            // Assert
            await waitFor(() => {
                expect(axios.get).toHaveBeenCalledWith("/api/v1/product/product-category/test-category-1");
            });
            expect(axios.get).toHaveBeenCalledTimes(1);

            // Clear mock for rerender
            axios.get.mockClear();

            // Arrange - Second side effect
            useParams.mockReturnValue({ slug: "test-category-2" });
            
            // Act - Rerender the component
            render(<CategoryProduct />);

            // Assert - Verify second API call with new slug
            await waitFor(() => {
                expect(axios.get).toHaveBeenCalledWith("/api/v1/product/product-category/test-category-2");
            });
            expect(axios.get).toHaveBeenCalledTimes(1);
        });
    })

    describe("useEffect is not triggered at all", () => {
        test.each([
            { description: "no slug property", params: {} },
            { description: "null slug", params: { slug: null } },
            { description: "undefined slug", params: { slug: undefined } },
            { description: "empty string slug", params: { slug: "" } },
        ])("should not call getProductsByCat when slug parameter is invalid ($description)", ({ params }) => {
            // Arrange
            useParams.mockReturnValue(params);

            // Act
            render(<CategoryProduct />);

            // Assert
            expect(axios.get).not.toHaveBeenCalled();
        });

        test("should not call getProductsByCat when slug parameter remains invalid", () => {
            // AAA - Does not trigger side effect
            useParams.mockReturnValue({});
            render(<CategoryProduct />);
            expect(axios.get).not.toHaveBeenCalled();

            // Clear mock for rerender
            axios.get.mockClear();

            // AAA - Does not trigger side effect
            useParams.mockReturnValue({});
            render(<CategoryProduct />);
            expect(axios.get).not.toHaveBeenCalled();
        });
    })

    describe("useEffect changes status from triggered to not triggered (vice versa)", () => {
        test("should trigger side effect when slug parameter changes from invalid to valid", async () => {
            // AAA - Does not trigger side effect
            useParams.mockReturnValue({});
            render(<CategoryProduct />);
            expect(axios.get).not.toHaveBeenCalled();

            // Clear mock for rerender
            axios.get.mockClear();

            // AAA - Triggers side effect
            useParams.mockReturnValue({ slug: "test-category" });
            render(<CategoryProduct />);
            await waitFor(() => {
                expect(axios.get).toHaveBeenCalledWith("/api/v1/product/product-category/test-category");
            });
            expect(axios.get).toHaveBeenCalledTimes(1);
        });

        test("should not trigger side effect when slug parameter changes from valid to invalid", async () => {
            // AAA - Triggers side effect
            useParams.mockReturnValue({ slug: "test-category" });
            render(<CategoryProduct />);
            await waitFor(() => {
                expect(axios.get).toHaveBeenCalledWith("/api/v1/product/product-category/test-category");
            });
            expect(axios.get).toHaveBeenCalledTimes(1);

            // Clear mock for rerender
            axios.get.mockClear();

            // AAA - Does not trigger side effect
            useParams.mockReturnValue({});
            render(<CategoryProduct />);
            expect(axios.get).not.toHaveBeenCalled();
        });
    })
});

describe("getProductsByCat test", () => {    
    // Set up & tear down
    beforeEach(() => { jest.clearAllMocks(); });
    afterEach(() => { jest.restoreAllMocks(); });

    // Happy Path: Testing done using UI components
    test("should display products in the UI if getProductsByCat is run successfully", async () => {
        // Arrange
        useParams.mockReturnValue({ slug: "electronics" });
        
        const expectedProducts = [
            {
                _id: "prod-123",
                name: "Laptop",
                slug: "laptop",
                description: "High performance laptop",
                price: 999.99,
                category: "cat-123",
                quantity: 10,
                shipping: true
            }
        ];

        const expectedCategory = {
            _id: "cat-123",
            name: "Electronics",
            slug: "electronics"
        };

        axios.get.mockResolvedValue({
            data: {
                products: expectedProducts,
                category: expectedCategory
            }
        });

        // Act
        render(<CategoryProduct />);
        
        // Assert
        await waitFor(() => {
            expect(axios.get).toHaveBeenCalledWith("/api/v1/product/product-category/electronics");

            // Check if UI components are correctly displayed
            expect(screen.getByText("Laptop")).toBeInTheDocument();
            expect(screen.getByText("$999.99")).toBeInTheDocument();
            expect(screen.getByText("Category - Electronics")).toBeInTheDocument();
            expect(screen.getByText("1 result found")).toBeInTheDocument();
            expect(screen.getByText(/High performance laptop/)).toBeInTheDocument();
            expect(screen.getByText("More Details")).toBeInTheDocument();
        });
    });

    // setPromise & setCategory does not return any errors
    test("catch block should handle axios.get promise rejects", async () => {
        // For error checking
        const consoleSpy = jest.spyOn(console, "log").mockImplementation(() => {});

        // Arrange
        useParams.mockReturnValue({ slug: "test-category" });
        const axiosError = new Error("Promise Rejected");
        axios.get.mockRejectedValueOnce(axiosError);

        // Act
        render(<CategoryProduct />);

        // Assert
        await waitFor(() => {
            expect(axios.get).toHaveBeenCalledWith("/api/v1/product/product-category/test-category");
            expect(consoleSpy).toHaveBeenCalledWith(axiosError);
        });
    });
});

describe("CategoryProduct Navigation", () => {
    const mockNavigate = jest.fn();
    const mockProducts = [
        {
            _id: "p1",
            name: "Product 1",
            slug: "product-1-slug",
            price: 99.99,
            description: "test description",
        },
    ];
    const mockCategory = { name: "Test Category" };

    beforeEach(() => {
        jest.clearAllMocks();
        useNavigate.mockReturnValue(mockNavigate);
        useParams.mockReturnValue({ slug: "test-category" });
    });

    // Visibility test
    test("should render the 'More Details' button after products load", async () => {
        // Arrange
        axios.get.mockResolvedValueOnce({
            data: { products: mockProducts, category: mockCategory },
        });

        // Act
        render(<CategoryProduct />);

        // Assert
        const detailsBtn = await screen.findByText("More Details");
        expect(detailsBtn).toBeInTheDocument();
    });

    // Interaction/Navigation test
    test("should navigate to the correct URL when 'More Details' is clicked", async () => {
        // Arrange
        axios.get.mockResolvedValueOnce({
            data: { products: mockProducts, category: mockCategory },
        });

        // Act
        render(<CategoryProduct />);
        const detailsBtn = await screen.findByText("More Details");
        fireEvent.click(detailsBtn);

        // Assert
        expect(mockNavigate).toHaveBeenCalledWith("/product/product-1-slug");
    });
});
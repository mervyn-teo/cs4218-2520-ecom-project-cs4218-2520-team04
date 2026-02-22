// Yeo Yi Wen, A0273575U
import React from "react";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import axios from "axios";
import { useParams, useNavigate } from "react-router-dom";
import ProductDetails from "./ProductDetails";

// Mock the dependencies
jest.mock("axios");
jest.mock("react-router-dom", () => ({
    ...jest.requireActual("react-router-dom"),
    useParams: jest.fn(),
    useNavigate: jest.fn(),
}));
jest.mock("./../components/Layout", () => {
    return ({ children }) => <div>{children}</div>;
});

describe("ProductDetails Component", () => {
    const mockNavigate = jest.fn();

    const mockProduct = {
        _id: "p1",
        name: "Test Product",
        description: "This is a test description.",
        price: 299.99,
        category: { _id: "c1", name: "Electronics" },
    };

    const mockRelatedProducts = [
        {
        _id: "p2",
        name: "Related Product 1",
        description: "Related description test.",
        price: 149.99,
        slug: "related-product-1",
        },
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        useNavigate.mockReturnValue(mockNavigate);
        useParams.mockReturnValue({ slug: "test-product" });
    });

    test("should render product details correctly after fetching data", async () => {
        // Arrange
        axios.get.mockImplementation((url) => {
            if (url.includes("/get-product/")) {
                return Promise.resolve({ data: { product: mockProduct } });
            }
            if (url.includes("/related-product/")) {
                return Promise.resolve({ data: { products: mockRelatedProducts } });
            }
            return Promise.reject(new Error("Not Found"));
        });

        // Act
        render(<ProductDetails />);
        const relatedItem = await screen.findByText("Related Product 1");
        
        // Assert
        expect(screen.getByText("Name : Test Product")).toBeInTheDocument();
        expect(screen.getByText("Description : This is a test description.")).toBeInTheDocument();
        expect(screen.getByText("Category : Electronics")).toBeInTheDocument();
        expect(relatedItem).toBeInTheDocument();
    });

    test("should render product details correctly", async () => {
        // Arrange
        axios.get.mockResolvedValueOnce({ data: { product: mockProduct } })
                .mockResolvedValueOnce({ data: { products: mockRelatedProducts } });

        // Act
        render(<ProductDetails />);

        // Assert
        expect(await screen.findByText(/Name : Test Product/i)).toBeInTheDocument();
        expect(screen.getByText(/Description : This is a test description./i)).toBeInTheDocument();
        expect(screen.getByText(/Category : Electronics/i)).toBeInTheDocument();
    });

    test("should display empty state message when no similar products exist", async () => {
        // Arrange
        axios.get.mockImplementation((url) => {
            if (url.includes("/get-product/")) {
                return Promise.resolve({ data: { product: mockProduct } });
            }
            if (url.includes("/related-product/")) {
                return Promise.resolve({ data: { products: [] } }); 
            }
            return Promise.reject(new Error("Not Found"));
        });

        // Act
        render(<ProductDetails />);

        // Assert - 1st API call
        await screen.findByText(/Name : Test Product/i);

        // Assert - 2nd State update
        await waitFor(() => {
            expect(screen.getByText("No Similar Products found")).toBeInTheDocument();
        });
    });

    test("should display the 'More Details' button when related products are loaded", async () => {
        // Arrange
        axios.get.mockImplementation((url) => {
            if (url.includes("/get-product/")) {
                return Promise.resolve({ data: { product: mockProduct } });
            }
            if (url.includes("/related-product/")) {
                return Promise.resolve({ data: { products: mockRelatedProducts } });
            }
            return Promise.reject(new Error("Not Found"));
        });

        // Act
        render(<ProductDetails />);

        // Assert
        const moreDetailsBtn = await screen.findByText("More Details");
        expect(moreDetailsBtn).toBeInTheDocument();
    });

    test("should navigate to the correct URL when 'More Details' is clicked", async () => {
        // Arrange
        axios.get.mockImplementation((url) => {
            if (url.includes("/get-product/")) {
                return Promise.resolve({ data: { product: mockProduct } });
            }
            if (url.includes("/related-product/")) {
                return Promise.resolve({ data: { products: mockRelatedProducts } });
            }
            return Promise.reject(new Error("Not Found"));
        });

        // Act
        render(<ProductDetails />);
        const moreDetailsBtn = await screen.findByText("More Details");
        fireEvent.click(moreDetailsBtn);

        // Assert
        expect(mockNavigate).toHaveBeenCalledWith("/product/related-product-1");
    });

    test("should handle errors gracefully without crashing for getProduct", async () => {
        // Arrange
        const consoleSpy = jest.spyOn(console, "log").mockImplementation(() => {});
        axios.get.mockRejectedValue(new Error("API Error"));

        // Act
        render(<ProductDetails />);

        // Assert
        await waitFor(() => {
            expect(consoleSpy).toHaveBeenCalledWith(expect.any(Error));
        });

        consoleSpy.mockRestore();
    });

    test("should handle errors gracefully without crashing for getSimilarProduct", async () => {
        // Arrange
        const consoleSpy = jest.spyOn(console, "log").mockImplementation(() => {});
        
        axios.get.mockImplementation((url) => {
            if (url.includes("/get-product/")) {
                return Promise.resolve({ data: { product: mockProduct } }); // Succeeds
            }
            if (url.includes("/related-product/")) {
                return Promise.reject(new Error("Similar Products API Error")); // Fails
            }
            return Promise.reject(new Error("Not Found"));
        });

        // Act
        render(<ProductDetails />);

        // Assert
        await waitFor(() => {
            expect(consoleSpy).toHaveBeenCalledWith(expect.any(Error));
        });

        consoleSpy.mockRestore();
    });
    
    test("should not fetch product if slug is not provided in params", () => {
        // Arrange
        useParams.mockReturnValue({});
        
        // Act
        render(<ProductDetails />);
        
        // Assert
        expect(axios.get).not.toHaveBeenCalled();
    });
});
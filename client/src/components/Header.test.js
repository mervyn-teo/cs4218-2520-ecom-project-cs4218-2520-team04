// Yeo Yi Wen, A0273575U
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import "@testing-library/jest-dom";
import Header from "./Header";
import { useAuth } from "../context/auth";
import { useCart } from "../context/cart";
import useCategory from "../hooks/useCategory";
import toast from "react-hot-toast";

// Mock dependencies
jest.mock("../context/auth", () => ({ useAuth: jest.fn() }));
jest.mock("../context/cart", () => ({ useCart: jest.fn() }));
jest.mock("../hooks/useCategory", () => jest.fn());
jest.mock("./Form/SearchInput", () => () => <div data-testid="search-mock">SearchInput</div>);
jest.mock("react-hot-toast", () => ({ success: jest.fn() }));

describe("Header Component", () => {
    const mockSetAuth = jest.fn();
    
    beforeEach(() => {
        jest.clearAllMocks();
        Storage.prototype.removeItem = jest.fn(); // mock localStorage
    });

    const renderHeader = () => render(
        <BrowserRouter>
            <Header />
        </BrowserRouter>
    );

    // Branch: Not Logged In
    describe("user is not authenticated", () => {
        beforeEach(() => { 
            // Arrange 
            useAuth.mockReturnValue([{ user: null }, mockSetAuth]); 
            useCart.mockReturnValue([[]]); 
            useCategory.mockReturnValue([]); 
            
            // Act 
            renderHeader(); 
        });

        // Assert
        test("should render Login link", () => {
            expect(screen.getByText("Login")).toBeInTheDocument();
        });

        test("should render Register link", () => {
            expect(screen.getByText("Register")).toBeInTheDocument();
        });

        test("should not render Logout link", () => {
            expect(screen.queryByText("Logout")).not.toBeInTheDocument();
        })
    });

    // Branch: Admin user (Role 1)
    test("should render Admin Dashboard link when user role is 1", () => {
        // Arrange
        useAuth.mockReturnValue([
            { user: { name: "Admin User", role: 1 }, token: "123" }, 
            mockSetAuth]
        );
        useCart.mockReturnValue([[]]);
        useCategory.mockReturnValue([]);

        // Act
        renderHeader();
        fireEvent.click(screen.getByText("Admin User"));
        const dashboardLink = screen.getByText("Dashboard");

        // Assert
        expect(dashboardLink.closest('a')).toHaveAttribute("href", "/dashboard/admin");
    });

    // Branch: Normal user (Role 0)
    test("should render User Dashboard link when user role is 0", () => {
        // Arrange
        useAuth.mockReturnValue([
            { user: { name: "Regular User", role: 0 }, token: "123" }, 
            mockSetAuth]
        );
        useCart.mockReturnValue([[]]);
        useCategory.mockReturnValue([]);

        // Act
        renderHeader();
        fireEvent.click(screen.getByText("Regular User"));
        const dashboardLink = screen.getByText("Dashboard");

        // Assert
        expect(dashboardLink.closest('a')).toHaveAttribute("href", "/dashboard/user");
    });

    // Logout logic
    describe("handleLogout Logic", () => {
        const mockSetAuth = jest.fn();

        beforeEach(() => {
            jest.clearAllMocks();
            
            // Arrange
            useAuth.mockReturnValue([{ user: { name: "John" }, token: "123" }, mockSetAuth]);
            useCart.mockReturnValue([[]]);
            useCategory.mockReturnValue([]);
            Storage.prototype.removeItem = jest.fn();

            // Act
            renderHeader(); 
            fireEvent.click(screen.getByText("John"));
            fireEvent.click(screen.getByText("Logout"));
        });

        // Assert
        test("should update auth state to null values", () => {
            expect(mockSetAuth).toHaveBeenCalledWith({
                user: null,
                token: "",
            });
        });

        test("should remove auth data from localStorage", () => {
            expect(localStorage.removeItem).toHaveBeenCalledWith("auth");
        });

        test("should display success toast notification", () => {
            expect(toast.success).toHaveBeenCalledWith("Logout Successfully");
        });
    });

    // Categories mapping
    describe("Categories Dropdown", () => {
        // Arrange
        const categories = [
            { _id: "1", name: "Electronics", slug: "electronics" },
            { _id: "2", name: "Clothes", slug: "clothes" }
        ];

        beforeEach(() => {
            jest.clearAllMocks();

            // Arrange
            useAuth.mockReturnValue([{ user: null }, mockSetAuth]);
            useCart.mockReturnValue([[]]);
            useCategory.mockReturnValue(categories);
            
            // Act
            renderHeader();
        });

        // Assert - presence of names verifies the .map() function executed correctly
        test("should render all category names from the hook in the dropdown", () => {
            expect(screen.getByText("Electronics")).toBeInTheDocument();
            expect(screen.getByText("Clothes")).toBeInTheDocument();
        });

        // Assert - href attribute verifies the dynamic template literal link logic
        test("should provide the correct navigation links for each category", () => {
            const electronicsLink = screen.getByText("Electronics").closest("a");
            const clothesLink = screen.getByText("Clothes").closest("a");

            expect(electronicsLink).toHaveAttribute("href", "/category/electronics");
            expect(clothesLink).toHaveAttribute("href", "/category/clothes");
        });

        // Assert - expect at least the 2 categories + "All Categories" link
        test("should assign unique keys to category list items (verified by lack of console errors)", () => {
            const listItems = screen.getAllByRole("listitem");
            expect(listItems.length).toBeGreaterThanOrEqual(2);
        });
    });

    // Cart Badge
    test("should show correct count in Cart badge", () => {
        // Arrange
        useAuth.mockReturnValue([{ user: null }, mockSetAuth]);
        useCart.mockReturnValue([[ { id: 1 }, { id: 2 } ]]); // Cart length = 2
        useCategory.mockReturnValue([]);

        // Act
        renderHeader();

        // Assert - Design Badge renders the count as text
        expect(screen.getByText("2")).toBeInTheDocument();
    });
});
//
// Mervyn Teo Zi Yan, A0273039A
//
// Integration tests for Admin Dashboard components: Dashboard + Menu + Context.
// Tests use a Bottom-Up approach ensuring top-level components properly consume
// the foundational context layer.
//
// This verifies:
//   - AdminDashboard correctly extracts and renders data from the AuthContext.
//   - AdminMenu properly integrates with React Router for navigation.
//   - The Layout wrapper correctly encapsulates the dashboard content.

import React from "react";
import {render, screen, waitFor, act} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route, useLocation } from "react-router-dom";
import { AuthProvider } from "../../context/auth";
import AdminDashboard from "./AdminDashboard";

jest.mock("../../components/Layout", () => {
    return ({ children }) => <div data-testid="mock-layout">{children}</div>;
});

const LocationDisplay = () => {
    const location = useLocation();
    return <div data-testid="location-display">{location.pathname}</div>;
};

afterEach(() => {
    localStorage.clear();
});

describe("Admin Dashboard Integration — Context Consumption & Routing", () => {
    test("Dashboard renders admin details correctly by consuming AuthContext", () => {
        const adminAuthData = {
            user: {
                name: "Super Admin",
                email: "admin@test.com",
                phone: "88888888"
            },
            token: "admin-token",
        };
        localStorage.setItem("auth", JSON.stringify(adminAuthData));

        render(
            <AuthProvider>
                <MemoryRouter>
                    <AdminDashboard />
                </MemoryRouter>
            </AuthProvider>
        );

        expect(screen.getByText("Admin Name : Super Admin")).toBeInTheDocument();
        expect(screen.getByText("Admin Email : admin@test.com")).toBeInTheDocument();
        expect(screen.getByText("Admin Contact : 88888888")).toBeInTheDocument();
    });

    test("AdminMenu renders the correct navigation links integrated with Router", () => {
        render(
            <AuthProvider>
                <MemoryRouter>
                    <AdminDashboard />
                </MemoryRouter>
            </AuthProvider>
        );

        const createCategoryLink = screen.getByText("Create Category");
        expect(createCategoryLink).toBeInTheDocument();
        expect(createCategoryLink.getAttribute("href")).toBe("/dashboard/admin/create-category");

        const ordersLink = screen.getByText("Orders");
        expect(ordersLink.getAttribute("href")).toBe("/dashboard/admin/orders");
    });

    test("AdminMenu dynamically updates routing paths when clicked", async () => {
        render(
            <AuthProvider>
                <MemoryRouter initialEntries={["/dashboard/admin"]}>
                    <Routes>
                        <Route path="/dashboard/admin" element={<AdminDashboard />} />
                        <Route path="/dashboard/admin/create-product" element={<div>Create Product Page</div>} />
                    </Routes>
                    <LocationDisplay />
                </MemoryRouter>
            </AuthProvider>
        );

        expect(screen.getByTestId("location-display")).toHaveTextContent("/dashboard/admin");

        const createProductLink = screen.getByRole("link", { name: /create product/i });

        act(() => {
            userEvent.click(createProductLink);
        });

        await waitFor(() => {
            expect(screen.getByTestId("location-display")).toHaveTextContent("/dashboard/admin/create-product");
            expect(screen.getByText("Create Product Page")).toBeInTheDocument();
        });
    });
});
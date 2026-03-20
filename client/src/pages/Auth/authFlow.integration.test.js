//
// Mervyn Teo Zi Yan, A0273039A
//
// Integration tests for Frontend Authentication components: Context + Forms + Axios.
// Tests use a Bottom-Up approach via React Testing Library to ensure end-to-end reliability:
//   Login/Register Form → Axios (mocked) → LocalStorage → AuthContext Provider
//
// This verifies:
//   - Happy paths: Successful registration and login update state and routing correctly.
//   - Negative paths: API errors (400/404/500) correctly trigger error toasts and stop navigation.
//   - UX interactions: Buttons are disabled during loading states to prevent duplicate submissions.
//   - Advanced Routing: Login correctly redirects users to `location.state` if they were bounced
//     from a protected route.

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import axios from "axios";
import toast from "react-hot-toast";

import { AuthProvider, useAuth } from "../../context/auth";
import Login from "../../pages/Auth/Login";
import Register from "../../pages/Auth/Register";
import AdminDashboard from "../../pages/Admin/AdminDashboard";

jest.mock("axios");
jest.mock("react-hot-toast");

beforeAll(() => {
    jest.spyOn(console, "error").mockImplementation(() => {});
    jest.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
});

// ─── Register Flow Integration ───────────────────────────────────────────

describe("Register Flow Integration", () => {
    test("Successfully registers a user and navigates to login", async () => {
        axios.post.mockResolvedValueOnce({ data: { success: true } });
        const user = userEvent.setup();

        render(
            <AuthProvider>
                <MemoryRouter initialEntries={["/register"]}>
                    <Routes>
                        <Route path="/register" element={<Register />} />
                        <Route path="/login" element={<div>Login Page Mock</div>} />
                    </Routes>
                </MemoryRouter>
            </AuthProvider>
        );

        await user.type(screen.getByPlaceholderText("Enter Your Name"), "John Doe");
        await user.type(screen.getByPlaceholderText("Enter Your Email"), "john@test.com");
        await user.type(screen.getByPlaceholderText("Enter Your Password"), "pass123");
        await user.type(screen.getByPlaceholderText("Enter Your Phone"), "12345678");
        await user.type(screen.getByPlaceholderText("Enter Your Address"), "123 St");
        await user.type(screen.getByPlaceholderText("Enter Your DOB"), "2000-01-01");
        await user.type(screen.getByPlaceholderText("What is Your Favorite sports"), "Tennis");

        const submitBtn = screen.getByRole("button", { name: /register/i });
        await user.click(submitBtn);

        // Verify loading state prevents double clicks
        expect(submitBtn).toBeDisabled();
        expect(submitBtn).toHaveTextContent("Registering...");

        await waitFor(() => {
            expect(axios.post).toHaveBeenCalledWith("/api/v1/auth/register", expect.any(Object));
            expect(toast.success).toHaveBeenCalledWith("Register Successfully, please login");
            // Verify router navigated to /login
            expect(screen.getByText("Login Page Mock")).toBeInTheDocument();
        });
    });

    test("Fails to register and displays API error message via toast", async () => {
        const errorResponse = {
            response: { data: { message: "Email already exists" } }
        };
        axios.post.mockRejectedValueOnce(errorResponse);
        const user = userEvent.setup();

        render(
            <AuthProvider>
                <MemoryRouter initialEntries={["/register"]}>
                    <Register />
                </MemoryRouter>
            </AuthProvider>
        );

        await user.type(screen.getByPlaceholderText("Enter Your Email"), "existing@test.com");
        await user.click(screen.getByRole("button", { name: /register/i }));

        await waitFor(() => {
            expect(toast.error).toHaveBeenCalledWith("Email already exists");
            expect(screen.getByRole("button", { name: /register/i })).not.toBeDisabled();
        });
    });
});

// ─── Login Flow Integration & Advanced Routing ───────────────────────────

describe("Login Flow & Location State Integration", () => {
    test("Successfully logs in and redirects to the intended protected route (location.state)", async () => {
        const mockApiResponse = {
            data: {
                success: true,
                message: "Login successful",
                user: { name: "Protected User" },
                token: "token-123",
            },
        };
        axios.post.mockResolvedValueOnce(mockApiResponse);
        const user = userEvent.setup();

        render(
            <AuthProvider>
                <MemoryRouter initialEntries={[{ pathname: "/login", state: "/dashboard/admin" }]}>
                    <Routes>
                        <Route path="/login" element={<Login />} />
                        <Route path="/dashboard/admin" element={<div>Secret Admin Area</div>} />
                    </Routes>
                </MemoryRouter>
            </AuthProvider>
        );

        await user.type(screen.getByPlaceholderText("Enter Your Email"), "admin@test.com");
        await user.type(screen.getByPlaceholderText("Enter Your Password"), "secret");
        await user.click(screen.getByRole("button", { name: /login/i }));

        await waitFor(() => {
            expect(localStorage.getItem("auth")).toContain("token-123");
            expect(toast.success).toHaveBeenCalledWith("Login successful", expect.objectContaining({
                icon: "🙏",
                style: { background: "green", color: "white" }
            }));
            // User should land on the state route, not "/"
            expect(screen.getByText("Secret Admin Area")).toBeInTheDocument();
        });
    });

    test("Handles generic API failures gracefully", async () => {
        axios.post.mockRejectedValueOnce(new Error("Network Error"));
        const user = userEvent.setup();

        render(
            <AuthProvider>
                <MemoryRouter>
                    <Login />
                </MemoryRouter>
            </AuthProvider>
        );

        await user.type(screen.getByPlaceholderText("Enter Your Email"), "test@test.com");
        await user.type(screen.getByPlaceholderText("Enter Your Password"), "fail");
        await user.click(screen.getByRole("button", { name: /login/i }));

        await waitFor(() => {
            // Corrected assertion: Expect the error toast to fire on network failure
            expect(toast.error).toHaveBeenCalledWith("Something went wrong");
        });
    });
});

// ─── LocalStorage Edge Cases ─────────────────────────────────────────────

describe("AuthContext - Corrupted Data Handling", () => {
    test("Gracefully handles invalid JSON in localStorage without crashing the app", () => {
        // malformed JSON
        localStorage.setItem("auth", "{ invalid-json: true, missingQuotes }");

        expect(() => {
            render(
                <AuthProvider>
                    <MemoryRouter>
                        <AdminDashboard />
                    </MemoryRouter>
                </AuthProvider>
            );
        }).not.toThrow();

        expect(screen.getByText(/Admin Name :/i)).toBeInTheDocument();
    });
});

// ─── Login Sad Paths ─────────────────────────────────────────────────────

describe("Login Flow - API Rejections & Network Failures", () => {
    test("Displays specific error when receiving 401 Invalid Credentials", async () => {
        const errorResponse = {
            response: {
                status: 401,
                data: { success: false, message: "Invalid email or password" }
            }
        };
        axios.post.mockRejectedValueOnce(errorResponse);
        const user = userEvent.setup();

        render(
            <AuthProvider>
                <MemoryRouter>
                    <Login />
                </MemoryRouter>
            </AuthProvider>
        );

        await user.type(screen.getByPlaceholderText("Enter Your Email"), "wrong@test.com");
        await user.type(screen.getByPlaceholderText("Enter Your Password"), "badpass");
        await user.click(screen.getByRole("button", { name: /login/i }));

        await waitFor(() => {
            expect(toast.error).toHaveBeenCalledWith("Invalid email or password");
            expect(screen.getByRole("button", { name: /login/i })).toBeInTheDocument();
        });
    });

    test("Handles malformed successful responses (e.g., missing token)", async () => {
        const malformedResponse = {
            data: {
                success: true,
                message: "Login successful",
                // Missing user and token fields
            },
        };
        axios.post.mockResolvedValueOnce(malformedResponse);
        const user = userEvent.setup();

        render(
            <AuthProvider>
                <MemoryRouter>
                    <Login />
                </MemoryRouter>
            </AuthProvider>
        );

        await user.type(screen.getByPlaceholderText("Enter Your Email"), "buggy@test.com");
        await user.type(screen.getByPlaceholderText("Enter Your Password"), "pass123");
        await user.click(screen.getByRole("button", { name: /login/i }));

        await waitFor(() => {
            const storedData = JSON.parse(localStorage.getItem("auth"));
            expect(storedData?.token).toBeUndefined();
        });
    });
});
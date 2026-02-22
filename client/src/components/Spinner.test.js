// Yeo Yi Wen, A0273575U
import React from "react";
import { render, screen, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Spinner from "./Spinner.js";

// Mock dependencies
const mockNavigate = jest.fn();
const mockLocation = { pathname: "/test-path" };
jest.mock("react-router-dom", () => ({
    ...jest.requireActual("react-router-dom"),
    useNavigate: () => mockNavigate,
    useLocation: () => mockLocation,
}));

describe("Spinner Component Navigation", () => {
    // Setup
    beforeEach(() => {
        // Arrange
        jest.useFakeTimers();
        jest.clearAllMocks();
        jest.spyOn(console, "warn").mockImplementation(() => {}); // Silence and track warnings
    });

    // Teardown
    afterEach(() => {
        jest.useRealTimers();
        console.warn.mockRestore();
    });

    // Visual Counter Flow
    test("should correctly display counter when it is decremented every second", () => {
        // Act
        render(
            <MemoryRouter>
                <Spinner />
            </MemoryRouter>
        );

        // Act & Assert
        expect(screen.getByText(/redirecting to you in 3 second/i)).toBeInTheDocument();

        act(() => {
            jest.advanceTimersByTime(1000);
        });

        expect(screen.getByText(/redirecting to you in 2 second/i)).toBeInTheDocument();

        act(() => {
            jest.advanceTimersByTime(1000);
        });

        expect(screen.getByText(/redirecting to you in 1 second/i)).toBeInTheDocument();

        act(() => {
            jest.advanceTimersByTime(1000);
        });

        expect(screen.getByText(/Loading.../i)).toBeInTheDocument();
    });

    // Invalid Paths (Redirection to /login)
    describe("Invalid Path Logic", () => {
        const invalidPaths = [
            ["empty string", ""],
            ["leading slash", "/dashboard"],
            ["trailing slash", "dashboard/"],
            ["double slashes", "user//settings"],
            ["traversal dots", "admin/../secrets"],
            ["invalid characters", "path$special"],
        ];

        test.each(invalidPaths)("should redirect to /login and warn when path is %s", (_, pathValue) => {
            // Act
            render(
                <MemoryRouter>
                    <Spinner path={pathValue} />
                </MemoryRouter>
            );

            act(() => {
                jest.advanceTimersByTime(3000);
            });

            // Assert
            expect(mockNavigate).toHaveBeenCalledWith("/login", {
                state: mockLocation.pathname,
            });
            
            // Verify that security warnings are being logged (except for empty string branch)
            if (pathValue !== "") {
                expect(console.warn).toHaveBeenCalled();
            }
        });
    });

    // Valid paths
    describe("Valid Path Logic", () => {
        // Arrange
        const validPaths = [
            ["dashboard", "/dashboard"], // single level
            ["user/profile", "/user/profile"], // nest link
            ["products/123", "/products/123"], // alphanumeric link
        ];

        test.each(validPaths)("should navigate to /%s when input is %s", (input, expected) => {
            // Act
            render(
                <MemoryRouter>
                    <Spinner path={input} />
                </MemoryRouter>
            );

            act(() => {
                jest.advanceTimersByTime(3000);
            });

            // Assert
            expect(mockNavigate).toHaveBeenCalledWith(expected, {
                state: mockLocation.pathname,
            });
        });
    });

    // --- TEST: Cleanup ---
    test("should clear interval on unmount", () => {
        const clearIntervalSpy = jest.spyOn(window, "clearInterval");
        const { unmount } = render(
        <MemoryRouter>
            <Spinner />
        </MemoryRouter>
        );

        unmount();
        expect(clearIntervalSpy).toHaveBeenCalled();
        clearIntervalSpy.mockRestore();
    });
});
// Yeo Yi Wen, A0273575U
import mongoose from "mongoose";
import connectDB from "./db";

jest.mock("mongoose", () => ({
    connect: jest.fn(),
}));

const mockConsoleLog = jest.spyOn(console, "log").mockImplementation(() => {});

// Setup and teardown
beforeEach(() => {
    jest.clearAllMocks();
});

afterAll(() => {
    mockConsoleLog.mockRestore();
});

describe("MongoDB Successful Connection with valid MONGO_URL", () => {
    // Top 3 most common MongoDB connection types
    const connectionTypes = [
        {
            name: "Local MongoDB",
            url: "mongodb://localhost:27017/testdb",
            host: "localhost:27017"
        },
        {
            name: "MongoDB Atlas",
            url: "mongodb+srv://user:password@cluster0.xyz.mongodb.net/testdb",
            host: "cluster0.xyz.mongodb.net"
        },
        {
            name: "Custom Port",
            url: "mongodb://192.168.x.x:27018/testdb",
            host: "192.168.x.x:27018"
        }
    ];

    connectionTypes.forEach(({ name, url, host }) => {
        test(`should connect to ${name} with valid URL: ${url}`, async () => {
            // Arrange
            process.env.MONGO_URL = url;
            
            mongoose.connect.mockResolvedValue({
                connection: { host }
            });

            // Act
            await connectDB();

            // Assert
            expect(mongoose.connect).toHaveBeenCalledWith(url);
            expect(console.log).toHaveBeenCalledWith(
                `Connected To Mongodb Database ${host}`.bgMagenta.white
            );
        });
    });
});

describe("MongoDB Failed Connection", () => {
    // Top 5 most common MongoDB connection errors
    const errorTypes = [
        {
            name: "connection refused",
            url: "mongodb://localhost:27017/testdb",
            error: new Error("ECONNREFUSED"),
        },
        {
            name: "authentication failed",
            url: "mongodb://user:wrongPassword@localhost:27017/testdb",
            error: new Error("Authentication failed"),
        },
        {
            name: "timeout",
            url: "mongodb://slow:27017/testdb",
            error: new Error("Timed out after 30000ms"),
        },
        {
            name: "invalid URL",
            url: "invalid-URL",
            error: new Error("Invalid MONGO_URL"),
        },
        {
            name: "missing URL",
            url: "",
            error: new Error("Missing MONGO_URL"),
        }
    ];

    errorTypes.forEach(({ name, url, error }) => {
        test(`should handle ${name} error`, async () => {
            // Arrange        
            process.env.MONGO_URL = url;
            mongoose.connect.mockRejectedValue(error);

            // Act
            await connectDB();

            // Assert
            expect(mongoose.connect).toHaveBeenCalledWith(url);
            expect(mockConsoleLog).toHaveBeenCalledWith(
                `Error in Mongodb ${error}`.bgRed.white
            );
        });
    });
});
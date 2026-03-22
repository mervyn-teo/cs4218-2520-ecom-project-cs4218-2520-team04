// Teo Kai Xiang, A0272558U
// Initial test template + mock helpers were written by me. Additional tests were generated and reviewed by GPT-5.3-Codex

import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/extend-expect";
import axios from "axios";
import HomePage from "./HomePage";
import { mockAxiosByUrl, mockAxiosByUrlWithError } from "../mocks/mockAxios";

const TITLE_TEXT = "All Products";
const PRODUCTS = [
  {
    _id: "p1",
    name: "Test Product",
    slug: "test-product",
    description: "A sample product description for testing",
    price: 12,
  },
  {
    _id: "p2",
    name: "Test Product2",
    slug: "test-product2",
    description: "A sample product description for testing2",
    price: 15,
  },
];
const FILTER_URL = "/api/v1/product/product-filters";
const CATEGORY_ONE = { _id: "c1", name: "Electronics" };
const CATEGORY_TWO = { _id: "c2", name: "Books" };
const CATEGORIES = [CATEGORY_ONE, CATEGORY_TWO];
const HAPPY_PATH_RESPONSES = {
  "/api/v1/category/get-category": {
    data: { success: true, category: [] },
  },
  "/api/v1/product/product-count": { data: { total: 2 } },
  "/api/v1/product/product-list/1": {
    data: {
      products: PRODUCTS,
    },
  },
};

const HAPPY_PATH_RESPONSES_EMPTY = {
  "/api/v1/category/get-category": {
    data: { success: true, category: [] },
  },
  "/api/v1/product/product-count": { data: { total: 0 } },
  "/api/v1/product/product-list/1": {
    data: {
      products: [],
    },
  },
};

const ERROR_RESPONSES = {
  "/api/v1/category/get-category": {
    response: {
      status: 500,
      data: { success: false, message: "Error while getting all categories" },
    },
    message: "Request failed with status code 500",
  },
  "/api/v1/product/product-count": {
    response: {
      status: 400,
      data: { success: false, message: "Error in product count" },
    },
    message: "Request failed with status code 400",
  },
  "/api/v1/product/product-list/1": {
    response: {
      status: 400,
      data: { success: false, message: "error in per page ctrl" },
    },
    message: "Request failed with status code 400",
  },
};

jest.mock("axios");

jest.mock("react-router-dom", () => ({
  ...jest.requireActual("react-router-dom"),
  useNavigate: () => jest.fn(),
}));

jest.mock("./../components/Layout", () => ({ children }) => (
  <div data-testid="layout">{children}</div>
));

jest.mock("../context/cart", () => ({
  useCart: () => [[], jest.fn()],
}));

describe("HomePage Component", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("Happy Path Tests - when everything works as expected, the component", () => {
    it("renders products returned from product list API on initial load", async () => {
      // Summary: Verifies the initial page load renders products returned by the product list API.
      // Flow: mock category/count/list endpoints -> render component -> assert heading and product names -> assert expected GET calls.
      // We mock the URL implementation instead as useEffect() means the order of API calls is not guaranteed, so we need to handle all possible calls in our mock implementation.
      // ------------ Arrange ------------
      mockAxiosByUrl(axios.get, HAPPY_PATH_RESPONSES);

      // Check React Functional Component actually renders - we will test it more completely in UI testing
      // ------------ Act ------------
      render(<HomePage />);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(screen.getByText(TITLE_TEXT)).toBeInTheDocument();
      });

      // Ensure all expected product data is rendered on the page
      await waitFor(() => {
        PRODUCTS.forEach((product) => {
          expect(screen.getByText(product.name)).toBeInTheDocument();
        });
      });

      // Ensures all URLs are called
      Object.keys(HAPPY_PATH_RESPONSES).forEach((url) => {
        expect(axios.get).toHaveBeenCalledWith(url);
      });
    });

    it("renders HomePage as usual when no products are listed", async () => {
      // Summary: Verifies the page shell still renders when the product list is empty.
      // Flow: mock empty category/count/list responses -> render component -> assert heading -> assert initial GET calls still execute.
      // We mock the URL implementation instead as useEffect() means the order of API calls is not guaranteed, so we need to handle all possible calls in our mock implementation.
      // ------------ Arrange ------------
      mockAxiosByUrl(axios.get, HAPPY_PATH_RESPONSES_EMPTY);

      // Check React Functional Component actually renders - we will test it more completely in UI testing
      // ------------ Act ------------
      render(<HomePage />);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(screen.getByText(TITLE_TEXT)).toBeInTheDocument();
      });

      // Ensures all URLs are called
      Object.keys(HAPPY_PATH_RESPONSES_EMPTY).forEach((url) => {
        expect(axios.get).toHaveBeenCalledWith(url);
      });
    });

    it("renders category checkboxes when category API succeeds", async () => {
      // Summary: Verifies successful category fetch populates the checkbox filter group.
      // Flow: mock category, count, and list responses -> render component -> assert both category checkboxes are visible.
      // ------------ Arrange ------------
      const responses = {
        "/api/v1/category/get-category": {
          data: { success: true, category: CATEGORIES },
        },
        "/api/v1/product/product-count": { data: { total: PRODUCTS.length } },
        "/api/v1/product/product-list/1": {
          data: { products: PRODUCTS },
        },
      };
      mockAxiosByUrl(axios.get, responses);

      // ------------ Act ------------
      render(<HomePage />);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(
          screen.getByRole("checkbox", { name: CATEGORY_ONE.name }),
        ).toBeInTheDocument();
        expect(
          screen.getByRole("checkbox", { name: CATEGORY_TWO.name }),
        ).toBeInTheDocument();
      });
      expect(axios.get).toHaveBeenCalledWith("/api/v1/category/get-category");
    });

    it("calls filter API with selected radio range when a price option is clicked", async () => {
      // Summary: Verifies selecting a price band sends the expected filter payload with page 1.
      // Flow: mock initial GET responses and filter POST response -> render component -> click price radio -> assert POST payload.
      // ------------ Arrange ------------
      const responses = {
        "/api/v1/category/get-category": {
          data: { success: true, category: [] },
        },
        "/api/v1/product/product-count": { data: { total: PRODUCTS.length } },
        "/api/v1/product/product-list/1": {
          data: { products: PRODUCTS },
        },
      };
      mockAxiosByUrl(axios.get, responses);
      mockAxiosByUrl(axios.post, {
        [FILTER_URL]: { data: { products: PRODUCTS, total: PRODUCTS.length } },
      });

      // ------------ Act ------------
      render(<HomePage />);
      const priceOption = await screen.findByRole("radio", {
        name: "$20 to 39",
      });
      fireEvent.click(priceOption);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(axios.post).toHaveBeenCalledWith(FILTER_URL, {
          checked: [],
          page: 1,
          radio: [20, 39],
        });
      });
    });

    it("calls filter API with selected category when a category checkbox is clicked", async () => {
      // Summary: Verifies selecting a category checkbox sends the expected category filter payload.
      // Flow: mock initial GET responses and filter POST response -> render component -> click category checkbox -> assert POST payload.
      // ------------ Arrange ------------
      const responses = {
        "/api/v1/category/get-category": {
          data: { success: true, category: CATEGORIES },
        },
        "/api/v1/product/product-count": { data: { total: PRODUCTS.length } },
        "/api/v1/product/product-list/1": {
          data: { products: PRODUCTS },
        },
      };
      mockAxiosByUrl(axios.get, responses);
      mockAxiosByUrl(axios.post, {
        [FILTER_URL]: { data: { products: PRODUCTS, total: PRODUCTS.length } },
      });

      // ------------ Act ------------
      render(<HomePage />);
      const categoryCheckbox = await screen.findByRole("checkbox", {
        name: CATEGORY_ONE.name,
      });
      fireEvent.click(categoryCheckbox);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(axios.post).toHaveBeenCalledWith(FILTER_URL, {
          checked: [CATEGORY_ONE._id],
          page: 1,
          radio: [],
        });
      });
    });

    it("removes unchecked category id from filter payload while preserving selected price filter", async () => {
      // Summary: Verifies unchecking a category removes it from the filter payload without clearing the chosen price filter.
      // Flow: mock initial/filter responses -> render component -> select price -> toggle category on and off -> assert last POST payload keeps only price range.
      // ------------ Arrange ------------
      const responses = {
        "/api/v1/category/get-category": {
          data: { success: true, category: CATEGORIES },
        },
        "/api/v1/product/product-count": { data: { total: PRODUCTS.length } },
        "/api/v1/product/product-list/1": {
          data: { products: PRODUCTS },
        },
      };
      mockAxiosByUrl(axios.get, responses);
      mockAxiosByUrl(axios.post, {
        [FILTER_URL]: { data: { products: PRODUCTS, total: PRODUCTS.length } },
      });

      // ------------ Act ------------
      render(<HomePage />);
      const priceOption = await screen.findByRole("radio", {
        name: "$20 to 39",
      });
      fireEvent.click(priceOption);

      const categoryCheckbox = await screen.findByRole("checkbox", {
        name: CATEGORY_ONE.name,
      });
      fireEvent.click(categoryCheckbox);
      fireEvent.click(categoryCheckbox);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(axios.post).toHaveBeenLastCalledWith(FILTER_URL, {
          checked: [],
          page: 1,
          radio: [20, 39],
        });
      });
    });

    it("uses product-list endpoint and does not call filter API when no filters are selected", async () => {
      // Summary: Verifies the page stays on the default product-list flow until a filter is actually selected.
      // Flow: mock initial GET responses -> render component -> assert products appear -> assert GET list called and POST filter not called.
      // ------------ Arrange ------------
      const responses = {
        "/api/v1/category/get-category": {
          data: { success: true, category: CATEGORIES },
        },
        "/api/v1/product/product-count": { data: { total: PRODUCTS.length } },
        "/api/v1/product/product-list/1": {
          data: { products: PRODUCTS },
        },
      };
      mockAxiosByUrl(axios.get, responses);

      // ------------ Act ------------
      render(<HomePage />);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(screen.getByText(PRODUCTS[0].name)).toBeInTheDocument();
      });
      expect(axios.get).toHaveBeenCalledWith("/api/v1/product/product-list/1");
      expect(axios.post).not.toHaveBeenCalled();
    });

    it("loads next page of products when Loadmore button is clicked and more products exist", async () => {
      // Summary: Verifies clicking Loadmore requests page two and appends the next product batch.
      // Flow: mock paginated GET responses -> render component -> click Loadmore -> assert page-two GET call and appended product text.
      // ------------ Arrange ------------
      const nextPageProducts = [
        {
          _id: "p3",
          name: "Page 2 Product",
          slug: "page-2-product",
          description: "A second page product description",
          price: 19,
        },
      ];
      const responses = {
        "/api/v1/category/get-category": {
          data: { success: true, category: [] },
        },
        "/api/v1/product/product-count": { data: { total: 2 } },
        "/api/v1/product/product-list/1": {
          data: { products: [PRODUCTS[0]] },
        },
        "/api/v1/product/product-list/2": {
          data: { products: nextPageProducts },
        },
      };
      mockAxiosByUrl(axios.get, responses);

      // ------------ Act ------------
      render(<HomePage />);
      const loadMoreButton = await screen.findByRole("button", {
        name: /loadmore/i,
      });
      fireEvent.click(loadMoreButton);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(axios.get).toHaveBeenCalledWith(
          "/api/v1/product/product-list/2",
        );
      });
      await waitFor(() => {
        expect(screen.getByText("Page 2 Product")).toBeInTheDocument();
      });
    });

    it("hides Loadmore button when all products are already loaded", async () => {
      // Summary: Verifies the pagination CTA is hidden once the loaded product count matches the total count.
      // Flow: mock count and page-one responses with all products already present -> render component -> assert Loadmore button is absent.
      // ------------ Arrange ------------
      const responses = {
        "/api/v1/category/get-category": {
          data: { success: true, category: [] },
        },
        "/api/v1/product/product-count": { data: { total: PRODUCTS.length } },
        "/api/v1/product/product-list/1": {
          data: { products: PRODUCTS },
        },
      };
      mockAxiosByUrl(axios.get, responses);

      // ------------ Act ------------
      render(<HomePage />);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(screen.getByText(PRODUCTS[0].name)).toBeInTheDocument();
      });
      expect(
        screen.queryByRole("button", { name: /loadmore/i }),
      ).not.toBeInTheDocument();
    });
  });

  describe("Unhappy Path Tests - when something breaks, the component", () => {
    it("handles API errors gracefully and does not crash the component", async () => {
      // Summary: Verifies failed initial API calls do not prevent the page shell from rendering.
      // Flow: mock errors for category, count, and list endpoints -> render component -> assert heading remains visible -> assert GET attempts still occurred.
      // ------------ Arrange ------------
      mockAxiosByUrlWithError(axios.get, ERROR_RESPONSES);

      // Check React Functional Component actually renders - we will test it more completely in UI testing
      // ------------ Act ------------
      render(<HomePage />);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(screen.getByText(TITLE_TEXT)).toBeInTheDocument();
      });

      // Ensures all URLs are called
      Object.keys(ERROR_RESPONSES).forEach((url) => {
        expect(axios.get).toHaveBeenCalledWith(url);
      });
    });

    it("does not render category checkboxes when category API returns success false", async () => {
      // Summary: Verifies unsuccessful category responses do not render stale or invalid checkbox options.
      // Flow: mock category API with success false plus valid count/list responses -> render component -> assert heading renders and category checkboxes stay hidden.
      // ------------ Arrange ------------
      const responses = {
        "/api/v1/category/get-category": {
          data: { success: false, category: CATEGORIES },
        },
        "/api/v1/product/product-count": { data: { total: PRODUCTS.length } },
        "/api/v1/product/product-list/1": {
          data: { products: PRODUCTS },
        },
      };
      mockAxiosByUrl(axios.get, responses);

      // ------------ Act ------------
      render(<HomePage />);

      // ------------ Assert ------------
      await waitFor(() => {
        expect(screen.getByText(TITLE_TEXT)).toBeInTheDocument();
      });
      expect(
        screen.queryByRole("checkbox", { name: CATEGORY_ONE.name }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByRole("checkbox", { name: CATEGORY_TWO.name }),
      ).not.toBeInTheDocument();
    });
  });
});

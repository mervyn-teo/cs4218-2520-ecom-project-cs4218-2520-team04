/**
 * By: Lu Yixuan, Deborah, A0277911X
 *
 * k6 Load Test Suite
 *
 * Scenarios:
 *   admin_users    - Admin users listing (GET /api/v1/auth/users)
 *   orders_user    - User orders retrieval (GET /api/v1/auth/orders)
 *   orders_admin   - Admin orders retrieval (GET /api/v1/auth/all-orders)
 *   order_status   - Admin order status update (PUT /api/v1/auth/order-status/:orderId)
 *   profile_update - User profile update (PUT /api/v1/auth/profile)
 *   search         - Product search (GET /api/v1/product/search/:keyword)
 *   mixed          - Weighted mix: search/orders_user/profile_update/admin_users
 *
 * Env vars:
 *   BASE_URL (default http://localhost:6060), SCENARIO (default mixed),
 *   VUS (default 30), RAMP_UP (15s), HOLD (30s), RAMP_DOWN (10s)
 *   ADMIN_EMAIL/ADMIN_PASS, USER_EMAIL/USER_PASS, KEYWORDS, ORDER_ID (optional)
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Trend, Rate, Counter } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL || "http://localhost:6060";
const SCENARIO = __ENV.SCENARIO || "mixed";

const ADMIN_EMAIL = __ENV.ADMIN_EMAIL || "test@admin.com";
const ADMIN_PASS = __ENV.ADMIN_PASS || "test@admin.com";
const USER_EMAIL = __ENV.USER_EMAIL || "user@test.com";
const USER_PASS = __ENV.USER_PASS || "user@test.com";

const KEYWORDS = (__ENV.KEYWORDS || "shirt,phone,book,laptop,shoes,watch")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const JSON_HEADERS = { "Content-Type": "application/json" };

function authHeaders(token) {
  return { ...JSON_HEADERS, Authorization: token };
}

const adminUsersDuration = new Trend("admin_users_duration", true);
const ordersUserDuration = new Trend("orders_user_duration", true);
const ordersAdminDuration = new Trend("orders_admin_duration", true);
const orderStatusDuration = new Trend("order_status_duration", true);
const profileUpdateDuration = new Trend("profile_update_duration", true);
const searchDuration = new Trend("search_duration", true);

const errorRate = new Rate("error_rate");
const totalReqs = new Counter("total_requests");

const LOAD_STAGES = [
  { duration: __ENV.RAMP_UP || "15s", target: Number(__ENV.VUS || 30) },
  { duration: __ENV.HOLD || "30s", target: Number(__ENV.VUS || 30) },
  { duration: __ENV.RAMP_DOWN || "10s", target: 0 },
];

export const options = {
  scenarios: buildScenarios(),
  thresholds: {
    http_req_failed: ["rate<0.02"],
    error_rate: ["rate<0.02"],

    admin_users_duration: ["p(95)<2000"],
    orders_user_duration: ["p(95)<2000"],
    orders_admin_duration: ["p(95)<2500"],
    order_status_duration: ["p(95)<2500"],
    profile_update_duration: ["p(95)<3000"],
    search_duration: ["p(95)<2000"],

    http_req_duration: ["p(95)<3000"],
  },
};

export function setup() {
  const adminToken = loginAndGetToken(ADMIN_EMAIL, ADMIN_PASS);
  const userToken = loginAndGetToken(USER_EMAIL, USER_PASS);

  let orderId = __ENV.ORDER_ID || "";
  if (!orderId && adminToken) {
    const res = http.get(`${BASE_URL}/api/v1/auth/all-orders`, {
      headers: authHeaders(adminToken),
      tags: { name: "GET /api/v1/auth/all-orders (setup)" },
    });

    if (res.status === 200) {
      try {
        const arr = JSON.parse(res.body);
        if (Array.isArray(arr) && arr.length > 0 && arr[0]._id) {
          orderId = arr[0]._id;
        }
      } catch {
        // ignore
      }
    }
  }

  return { adminToken, userToken, orderId };
}

function loginAndGetToken(email, password) {
  const payload = JSON.stringify({ email, password });

  const res = http.post(`${BASE_URL}/api/v1/auth/login`, payload, {
    headers: JSON_HEADERS,
    tags: { name: "POST /api/v1/auth/login" },
  });

  totalReqs.add(1);

  const ok = check(res, {
    "login: status 200": (r) => r.status === 200,
    "login: token exists": (r) => {
      try {
        return !!JSON.parse(r.body).token;
      } catch {
        return false;
      }
    },
  });

  errorRate.add(!ok);

  if (res.status !== 200) return "";
  try {
    return JSON.parse(res.body).token || "";
  } catch {
    return "";
  }
}

function buildScenarios() {
  const all = {
    admin_users_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: LOAD_STAGES,
      exec: "adminUsersScenario",
      tags: { scenario: "admin_users" },
    },
    orders_user_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: LOAD_STAGES,
      exec: "ordersUserScenario",
      tags: { scenario: "orders_user" },
    },
    orders_admin_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: LOAD_STAGES,
      exec: "ordersAdminScenario",
      tags: { scenario: "orders_admin" },
    },
    order_status_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: LOAD_STAGES,
      exec: "orderStatusScenario",
      tags: { scenario: "order_status" },
    },
    profile_update_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: LOAD_STAGES,
      exec: "profileUpdateScenario",
      tags: { scenario: "profile_update" },
    },
    search_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: LOAD_STAGES,
      exec: "searchScenario",
      tags: { scenario: "search" },
    },
    mixed_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: LOAD_STAGES,
      exec: "mixedScenario",
      tags: { scenario: "mixed" },
    },
  };

  const key = `${SCENARIO}_load`;
  if (!all[key]) {
    throw new Error(
      `Unknown SCENARIO "${SCENARIO}". Valid: admin_users, orders_user, orders_admin, order_status, profile_update, search, mixed`
    );
  }
  return { [key]: all[key] };
}

export function adminUsersScenario(data) {
  group("admin_users", () => {
    const res = http.get(`${BASE_URL}/api/v1/auth/users`, {
      headers: authHeaders(data.adminToken),
      tags: { name: "GET /api/v1/auth/users" },
    });

    adminUsersDuration.add(res.timings.duration);
    totalReqs.add(1);

    const ok = check(res, { "admin users: 200": (r) => r.status === 200 });
    errorRate.add(!ok);
  });

  sleep(0.2);
}

export function ordersUserScenario(data) {
  group("orders_user", () => {
    const res = http.get(`${BASE_URL}/api/v1/auth/orders`, {
      headers: authHeaders(data.userToken),
      tags: { name: "GET /api/v1/auth/orders" },
    });

    ordersUserDuration.add(res.timings.duration);
    totalReqs.add(1);

    const ok = check(res, {
      "orders(user): 200": (r) => r.status === 200,
      "orders(user): JSON array": (r) => {
        try {
          return Array.isArray(JSON.parse(r.body));
        } catch {
          return false;
        }
      },
    });

    errorRate.add(!ok);
  });

  sleep(0.2);
}

export function ordersAdminScenario(data) {
  group("orders_admin", () => {
    const res = http.get(`${BASE_URL}/api/v1/auth/all-orders`, {
      headers: authHeaders(data.adminToken),
      tags: { name: "GET /api/v1/auth/all-orders" },
    });

    ordersAdminDuration.add(res.timings.duration);
    totalReqs.add(1);

    const ok = check(res, {
      "orders(admin): 200": (r) => r.status === 200,
      "orders(admin): JSON array": (r) => {
        try {
          return Array.isArray(JSON.parse(r.body));
        } catch {
          return false;
        }
      },
    });

    errorRate.add(!ok);
  });

  sleep(0.2);
}

export function orderStatusScenario(data) {
  group("order_status", () => {
    if (!data.orderId) return;

    const statuses = ["Not Process", "Processing", "Shipped", "delivered", "cancel"];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const payload = JSON.stringify({ status });

    const res = http.put(
      `${BASE_URL}/api/v1/auth/order-status/${data.orderId}`,
      payload,
      {
        headers: authHeaders(data.adminToken),
        tags: { name: "PUT /api/v1/auth/order-status/:orderId" },
      }
    );

    orderStatusDuration.add(res.timings.duration);
    totalReqs.add(1);

    const ok = check(res, { "order-status: 200": (r) => r.status === 200 });
    errorRate.add(!ok);
  });

  sleep(0.2);
}

export function profileUpdateScenario(data) {
  group("profile_update", () => {
    const payload = JSON.stringify({
      name: `LoadUser_${__VU}_${__ITER}`,
      phone: "90000002",
      address: "Load Test Address",
      password: "",
      email: "",
    });

    const res = http.put(`${BASE_URL}/api/v1/auth/profile`, payload, {
      headers: authHeaders(data.userToken),
      tags: { name: "PUT /api/v1/auth/profile" },
    });

    profileUpdateDuration.add(res.timings.duration);
    totalReqs.add(1);

    const ok = check(res, { "profile update: 200/400": (r) => [200, 400].includes(r.status) });
    errorRate.add(!ok);
  });

  sleep(0.2);
}

export function searchScenario() {
  group("search", () => {
    const kw = KEYWORDS[Math.floor(Math.random() * KEYWORDS.length)];
    const res = http.get(`${BASE_URL}/api/v1/product/search/${encodeURIComponent(kw)}`, {
      tags: { name: "GET /api/v1/product/search/:keyword" },
    });

    searchDuration.add(res.timings.duration);
    totalReqs.add(1);

    const ok = check(res, {
      "search: 200": (r) => r.status === 200,
      "search: JSON array": (r) => {
        try {
          return Array.isArray(JSON.parse(r.body));
        } catch {
          return false;
        }
      },
    });

    errorRate.add(!ok);
  });

  sleep(0.2);
}

export function mixedScenario(data) {
  const r = Math.random();
  if (r < 0.60) return searchScenario();
  if (r < 0.80) return ordersUserScenario(data);
  if (r < 0.95) return profileUpdateScenario(data);
  return adminUsersScenario(data);
}
// Parses sample payloads with the Zod schemas. The response samples are copies of what the
// example server answered (`make example`), including timestamps with six and nine fractional
// digits as serde and Postgres write them. Run with `pnpm test` (Node strips the types).

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  AUTH_ERROR_CODES,
  authRoutes,
  createUserRequestSchema,
  errorResponseSchema,
  registerRequestSchema,
  retryAfterSecs,
  sessionListBodySchema,
  setupStatusBodySchema,
  signInBodySchema,
  updateUserRequestSchema,
  userBodySchema,
  userListBodySchema,
} from "@rustauth/contracts";

const admin = {
  id: "01a21911-ec12-7385-902d-97a55e7cf894",
  username: "admin",
  displayName: "Admin",
  role: "administrator",
  disabled: false,
  createdAt: "2026-11-26T18:15:34.353004Z",
  updatedAt: "2026-11-26T18:15:34.353004Z",
};

/** The first issue's message, or `undefined` when parsing succeeded. */
function issue(result: { success: boolean; error?: { issues: { message: string }[] } }) {
  return result.success ? undefined : result.error?.issues[0]?.message;
}

describe("responses", () => {
  test("setup status", () => {
    const body = setupStatusBodySchema.parse({
      data: { needsSetup: true, registrationOpen: false },
    });
    assert.deepEqual(body.data, { needsSetup: true, registrationOpen: false });
  });

  test("sign-in with a nanosecond expiry", () => {
    const body = signInBodySchema.parse({
      data: {
        token: "DJfZzvbsFkdvtMYcOqM0Kf7g5wZ_Reu6TLwhsF8RKDY",
        expiresAt: "2026-12-26T18:15:34.680729334Z",
        user: admin,
      },
    });
    assert.equal(body.data.user.role, "administrator");
    assert.equal(body.data.expiresAt, "2026-12-26T18:15:34.680729334Z");
  });

  test("sessions list", () => {
    const body = sessionListBodySchema.parse({
      items: [
        {
          id: "01a21911-ec18-76f6-861e-f709a14da803",
          current: true,
          methods: ["password"],
          assurance: "aal1",
          createdAt: "2026-11-26T18:15:34.680729Z",
          lastUsedAt: "2026-11-26T18:15:34.680729Z",
          expiresAt: "2026-12-26T18:15:34.680729Z",
          userAgent: "example/1.0",
          ip: "127.0.0.1",
        },
      ],
      total: 1,
    });
    assert.equal(body.items[0]?.current, true);
  });

  test("users list with a locked account", () => {
    const body = userListBodySchema.parse({
      items: [
        admin,
        {
          id: "01a21911-eda7-756b-9834-1745314da6ac",
          username: "widget_maker",
          displayName: "Widget Maker",
          role: "manager",
          disabled: false,
          lockedUntil: "2026-11-26T18:30:35.746530Z",
          createdAt: "2026-11-26T18:15:34.739332Z",
          updatedAt: "2026-11-26T18:15:34.739332Z",
        },
      ],
      total: 2,
    });
    assert.equal(body.items[1]?.lockedUntil, "2026-11-26T18:30:35.746530Z");
    assert.equal(body.items[0]?.lockedUntil, undefined);
  });

  test("a newer server's additions do not break parsing", () => {
    const body = userBodySchema.parse({
      data: { ...admin, role: "auditor", avatarUrl: "https://example.com/a.png" },
    });
    assert.equal(body.data.role, "user");
    assert.equal("avatarUrl" in body.data, false);
  });

  test("a response with a malformed id or timestamp fails", () => {
    assert.equal(userBodySchema.safeParse({ data: { ...admin, id: "7" } }).success, false);
    assert.equal(
      userBodySchema.safeParse({ data: { ...admin, createdAt: "yesterday" } }).success,
      false
    );
  });
});

describe("errors", () => {
  test("lockout carries the wait in seconds", () => {
    const body = errorResponseSchema.parse({
      error: "Too many failed sign-in attempts. Try again in 15 minutes.",
      code: "ACCOUNT_LOCKED",
      details: { retryAfterSecs: 900 },
      requestId: "example-request-1",
    });
    assert.equal(retryAfterSecs(body), 900);
  });

  test("validation names the field", () => {
    const body = errorResponseSchema.parse({
      error: "Username must be 3 to 32 characters long.",
      code: "VALIDATION_ERROR",
      field: "username",
    });
    assert.equal(body.field, "username");
    assert.equal(retryAfterSecs(body), undefined);
  });

  test("not found names the entity", () => {
    const body = errorResponseSchema.parse({
      error: "User not found.",
      code: "ENTITY_NOT_FOUND",
      details: { entityName: "User" },
    });
    assert.equal(retryAfterSecs(body), undefined);
    assert.ok(AUTH_ERROR_CODES.some((code) => code === body.code));
  });

  test("an unknown code still parses", () => {
    const body = errorResponseSchema.parse({ error: "Later.", code: "SOMETHING_NEW" });
    assert.equal(body.code, "SOMETHING_NEW");
  });
});

describe("requests", () => {
  const registration = {
    username: "  Alice_99 ",
    password: "a long password",
    displayName: " Alice ",
    setupToken: "example-setup-token-0123456789",
  };

  test("registration trims like the server", () => {
    const body = registerRequestSchema.parse(registration);
    assert.equal(body.username, "Alice_99");
    assert.equal(body.displayName, "Alice");
  });

  test("usernames follow the server rules and messages", () => {
    const parse = (username: string) =>
      issue(registerRequestSchema.safeParse({ ...registration, username }));
    assert.equal(parse("ab"), "Username must be 3 to 32 characters long.");
    assert.equal(parse("a".repeat(33)), "Username must be 3 to 32 characters long.");
    assert.equal(parse("alice-99"), "Username may contain only letters, digits, and underscores.");
    assert.equal(parse("a".repeat(32)), undefined);
  });

  test("display names count characters and refuse control characters", () => {
    const parse = (displayName: string) =>
      issue(registerRequestSchema.safeParse({ ...registration, displayName }));
    assert.equal(parse("   "), "Display name is required.");
    assert.equal(parse("😀".repeat(80)), undefined);
    assert.equal(parse("😀".repeat(81)), "Display name must be at most 80 characters long.");
    assert.equal(parse("Alice\u0007"), "Display name must not contain control characters.");
  });

  test("passwords are measured in UTF-8 bytes", () => {
    const parse = (password: string) =>
      issue(registerRequestSchema.safeParse({ ...registration, password }));
    assert.equal(parse("a".repeat(11)), "Password must be at least 12 characters long.");
    assert.equal(parse("😀😀😀"), undefined);
    assert.equal(parse("a".repeat(256)), undefined);
    assert.equal(parse("a".repeat(257)), "Password must be at most 256 bytes long.");
  });

  test("requests accept only known roles", () => {
    const account = {
      username: "widget_maker",
      displayName: "Widget Maker",
      temporaryPassword: "temporary password",
      role: "manager",
    };
    assert.equal(createUserRequestSchema.safeParse(account).success, true);
    assert.equal(createUserRequestSchema.safeParse({ ...account, role: "auditor" }).success, false);
    assert.deepEqual(updateUserRequestSchema.parse({ disabled: true }), { disabled: true });
  });
});

test("routes encode ids", () => {
  assert.equal(authRoutes.user("a/b"), "/admin/users/a%2Fb");
  assert.equal(authRoutes.unlockUser("42"), "/admin/users/42/unlock");
  assert.equal(authRoutes.session("42"), "/auth/sessions/42");
});

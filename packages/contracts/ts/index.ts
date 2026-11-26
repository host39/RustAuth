// Zod schemas for the RustAuth HTTP contracts. The Rust structs in `crates/rustauth-contracts/` are
// the source of truth: `make contracts` regenerates the types in `ts/generated/`, and each schema
// below must satisfy its generated type, so drift fails `make type-check`.
//
// The package ships TypeScript sources: applications compile them with their own bundler (see
// `docs/integration.md`). Internal imports use the `#generated/*` subpath import from
// package.json, so they resolve the same way inside this repository and in applications that
// install the package from git. They are type-only, so bundlers never resolve them at run time.
//
// Request schemas repeat the server's input rules and messages for form validation; the server
// stays the authority and answers `400 VALIDATION_ERROR` with the failing `field`. Response
// schemas accept what a newer server may add within the same major version: unknown fields are
// dropped, and an unknown role reads as `user`.

import { z } from "zod";
import type { ChangePasswordRequest } from "#generated/ChangePasswordRequest";
import type { CreateUserRequest } from "#generated/CreateUserRequest";
import type { ErrorResponse } from "#generated/ErrorResponse";
import type { ListUsersQuery } from "#generated/ListUsersQuery";
import type { LoginRequest } from "#generated/LoginRequest";
import type { RegisterRequest } from "#generated/RegisterRequest";
import type { SessionResponse } from "#generated/SessionResponse";
import type { SetupStatusResponse } from "#generated/SetupStatusResponse";
import type { SignInResponse } from "#generated/SignInResponse";
import type { UpdateProfileRequest } from "#generated/UpdateProfileRequest";
import type { UpdateUserRequest } from "#generated/UpdateUserRequest";
import type { UserResponse } from "#generated/UserResponse";
import type { UserRole } from "#generated/UserRole";

export type { ChangePasswordRequest } from "#generated/ChangePasswordRequest";
export type { CreateUserRequest } from "#generated/CreateUserRequest";
export type { DetailsResponse } from "#generated/DetailsResponse";
export type { ErrorResponse } from "#generated/ErrorResponse";
export type { ListResponse } from "#generated/ListResponse";
export type { ListUsersQuery } from "#generated/ListUsersQuery";
export type { LoginRequest } from "#generated/LoginRequest";
export type { RegisterRequest } from "#generated/RegisterRequest";
export type { SessionResponse } from "#generated/SessionResponse";
export type { SetupStatusResponse } from "#generated/SetupStatusResponse";
export type { SignInResponse } from "#generated/SignInResponse";
export type { UpdateProfileRequest } from "#generated/UpdateProfileRequest";
export type { UpdateUserRequest } from "#generated/UpdateUserRequest";
export type { UserResponse } from "#generated/UserResponse";
export type { UserRole } from "#generated/UserRole";

/** Request header whose value error bodies echo as `requestId`. */
export const REQUEST_ID_HEADER = "X-Request-Id";

/** Routes relative to where the application mounts the auth router (for example `/api`). */
export const authRoutes = {
  setup: "/auth/setup",
  register: "/auth/register",
  login: "/auth/login",
  logout: "/auth/logout",
  me: "/auth/me",
  password: "/auth/password",
  sessions: "/auth/sessions",
  session: (id: string) => `/auth/sessions/${encodeURIComponent(id)}`,
  revokeOtherSessions: "/auth/sessions/revoke-others",
  users: "/admin/users",
  user: (id: string) => `/admin/users/${encodeURIComponent(id)}`,
  unlockUser: (id: string) => `/admin/users/${encodeURIComponent(id)}/unlock`,
} as const;

/** Error codes the auth routes answer with. New codes may appear; handle unknown ones generically. */
export const AUTH_ERROR_CODES = [
  "INVALID_CREDENTIALS",
  "UNAUTHORIZED",
  "FORBIDDEN",
  "VALIDATION_ERROR",
  "ENTITY_NOT_FOUND",
  "USERNAME_TAKEN",
  "SETUP_REQUIRED",
  "REGISTRATION_CLOSED",
  "LAST_ADMINISTRATOR",
  "USER_IN_USE",
  "RATE_LIMITED",
  "ACCOUNT_LOCKED",
  "INTERNAL_ERROR",
  "PAYLOAD_TOO_LARGE",
  "UNSUPPORTED_MEDIA_TYPE",
] as const;

/** A code from {@link AUTH_ERROR_CODES}. `ErrorResponse.code` stays a `string`, since codes may grow. */
export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[number];

/** Every role, from highest to lowest. */
export const USER_ROLES = [
  "administrator",
  "manager",
  "user",
] as const satisfies readonly UserRole[];

/** Position in {@link USER_ROLES} (0 is the highest), or -1 for a value that is not a known role. */
function rank(role: unknown): number {
  return USER_ROLES.indexOf(role as UserRole);
}

/**
 * Whether `role` is `minimum` or higher (`administrator > manager > user`), like the server's
 * `Principal::has_role`. For showing or hiding UI only: the server checks every request.
 *
 * Fails closed: a role it does not know (from a newer server, or a value that skipped the
 * response schemas) reads as `user`, the lowest, and a `minimum` it does not know is never met.
 */
export function hasRole(role: UserRole, minimum: UserRole): boolean {
  const needed = rank(minimum);
  if (needed === -1) return false;
  const held = rank(role);
  return (held === -1 ? USER_ROLES.length - 1 : held) <= needed;
}

/**
 * Seconds to wait before retrying, from `details.retryAfterSecs` of a `429` body
 * (`RATE_LIMITED` or `ACCOUNT_LOCKED`). Browsers cannot read `Retry-After` across origins unless
 * the server exposes it, so the body repeats it.
 */
export function retryAfterSecs(error: ErrorResponse): number | undefined {
  const { retryAfterSecs: value } = error.details ?? {};
  return typeof value === "number" && value >= 0 ? value : undefined;
}

const utf8 = new TextEncoder();
const control = /\p{Cc}/u;

/** Length in UTF-8 bytes, as the server measures passwords. */
function bytes(value: string): number {
  return utf8.encode(value).length;
}

/** Length in Unicode code points, as the server counts characters. */
function chars(value: string): number {
  return Array.from(value).length;
}

const timestamp = z.iso.datetime({ offset: true });

/** 3 to 32 letters, digits, or underscores; surrounding whitespace is ignored. */
const username = z
  .string()
  .trim()
  .refine(
    (value) => chars(value) >= 3 && chars(value) <= 32,
    "Username must be 3 to 32 characters long."
  )
  .regex(/^[A-Za-z0-9_]*$/, "Username may contain only letters, digits, and underscores.");

/** 1 to 80 characters after trimming, without control characters. */
const displayName = z
  .string()
  .trim()
  .min(1, "Display name is required.")
  .refine((value) => chars(value) <= 80, "Display name must be at most 80 characters long.")
  .refine((value) => !control.test(value), "Display name must not contain control characters.");

/** 12 to 256 UTF-8 bytes. */
const newPassword = z
  .string()
  .refine((value) => bytes(value) >= 12, "Password must be at least 12 characters long.")
  .refine((value) => bytes(value) <= 256, "Password must be at most 256 bytes long.");

export const errorResponseSchema = z.object({
  error: z.string(),
  code: z.string().optional(),
  field: z.string().optional(),
  details: z.record(z.string(), z.json()).optional(),
  requestId: z.string().optional(),
}) satisfies z.ZodType<ErrorResponse>;

/** `{ items, total }` list envelope around `item`. */
export function listResponseSchema<T extends z.ZodType>(item: T) {
  return z.object({
    items: z.array(item),
    total: z.number().int().nonnegative(),
  });
}

/** `{ data }` details envelope around `data`. */
export function detailsResponseSchema<T extends z.ZodType>(data: T) {
  return z.object({ data });
}

/** A known role, for requests and forms. */
export const userRoleSchema = z.enum(USER_ROLES) satisfies z.ZodType<UserRole>;

/** A role in a response: a role added by a newer server reads as the lowest role, `user`. */
const responseRole = z
  .string()
  .transform((value): UserRole => userRoleSchema.safeParse(value).data ?? "user");

export const userResponseSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  displayName: z.string(),
  role: responseRole,
  disabled: z.boolean(),
  lockedUntil: timestamp.optional(),
  createdAt: timestamp,
  updatedAt: timestamp,
}) satisfies z.ZodType<UserResponse>;

export const setupStatusResponseSchema = z.object({
  needsSetup: z.boolean(),
  registrationOpen: z.boolean(),
}) satisfies z.ZodType<SetupStatusResponse>;

export const registerRequestSchema = z.object({
  username,
  password: newPassword,
  displayName,
  setupToken: z.string().min(1).optional(),
}) satisfies z.ZodType<RegisterRequest>;

export const loginRequestSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
}) satisfies z.ZodType<LoginRequest>;

export const signInResponseSchema = z.object({
  token: z.string(),
  expiresAt: timestamp,
  user: userResponseSchema,
}) satisfies z.ZodType<SignInResponse>;

export const updateProfileRequestSchema = z.object({
  displayName,
}) satisfies z.ZodType<UpdateProfileRequest>;

export const changePasswordRequestSchema = z.object({
  current: z.string().min(1),
  new: newPassword,
}) satisfies z.ZodType<ChangePasswordRequest>;

export const sessionResponseSchema = z.object({
  id: z.uuid(),
  current: z.boolean(),
  methods: z.array(z.string()),
  assurance: z.string(),
  createdAt: timestamp,
  lastUsedAt: timestamp,
  expiresAt: timestamp,
  userAgent: z.string(),
  ip: z.string().optional(),
}) satisfies z.ZodType<SessionResponse>;

export const listUsersQuerySchema = z.object({
  offset: z.number().int().nonnegative().optional(),
  limit: z.number().int().min(1).max(100).optional(),
}) satisfies z.ZodType<ListUsersQuery>;

export const createUserRequestSchema = z.object({
  username,
  displayName,
  temporaryPassword: newPassword,
  role: userRoleSchema,
}) satisfies z.ZodType<CreateUserRequest>;

export const updateUserRequestSchema = z.object({
  displayName: displayName.optional(),
  role: userRoleSchema.optional(),
  disabled: z.boolean().optional(),
  password: newPassword.optional(),
}) satisfies z.ZodType<UpdateUserRequest>;

/** `GET /auth/setup` */
export const setupStatusBodySchema = detailsResponseSchema(setupStatusResponseSchema);
/** `POST /auth/register` and `POST /auth/login` */
export const signInBodySchema = detailsResponseSchema(signInResponseSchema);
/** `GET` and `PATCH /auth/me`, `GET`, `POST`, and `PATCH /admin/users[/{id}]` */
export const userBodySchema = detailsResponseSchema(userResponseSchema);
/** `GET /auth/sessions` */
export const sessionListBodySchema = listResponseSchema(sessionResponseSchema);
/** `GET /admin/users` */
export const userListBodySchema = listResponseSchema(userResponseSchema);

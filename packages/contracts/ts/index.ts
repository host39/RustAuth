// Zod schemas for the RustAuth HTTP contracts. The Rust structs in `crates/rustauth-contracts/` are
// the source of truth: `make contracts` regenerates the types in `ts/generated/`, and each schema
// below must satisfy its generated type, so drift fails `make type-check`.
//
// Internal imports use the `#generated/*` subpath import from package.json, so they resolve the
// same way inside this repository and in applications that install the package from git.
//
// Request schemas repeat the server's input rules for form validation; the server stays the
// authority and answers `400 VALIDATION_ERROR` with the failing `field`.

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
  "RATE_LIMITED",
  "ACCOUNT_LOCKED",
  "INTERNAL_ERROR",
  "PAYLOAD_TOO_LARGE",
  "UNSUPPORTED_MEDIA_TYPE",
] as const;

/** Every role, from highest to lowest. */
export const USER_ROLES = [
  "administrator",
  "manager",
  "user",
] as const satisfies readonly UserRole[];

const timestamp = z.iso.datetime({ offset: true });

/** 3 to 32 letters, digits, or underscores; surrounding whitespace is ignored. */
const username = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9_]{3,32}$/, "Use 3 to 32 letters, digits, or underscores.");

/** 1 to 80 characters after trimming. */
const displayName = z.string().trim().min(1).max(80);

/** At least 12 characters (the server counts at least 12 and at most 256 UTF-8 bytes). */
const newPassword = z.string().min(12).max(256);

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

export const userRoleSchema = z.enum(USER_ROLES) satisfies z.ZodType<UserRole>;

export const userResponseSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  displayName: z.string(),
  role: userRoleSchema,
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

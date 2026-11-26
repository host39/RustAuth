//! The guard layer: reads `Authorization: Bearer`, calls `AuthService::verify`, and inserts
//! `AuthUser` into the request extensions, or answers `401` with the error body.

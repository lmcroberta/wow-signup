# WoW Signup and Willa Rose Wardrobe changelog

## 1.2.4 — 2026-10-15

- Added a fixed bridge operation that creates fresh quartermaster entry 9,100,003 as a byte-for-byte clone of visible donor Jaluu, changing only its entry, name, and subname.
- The operation clears only entry 9,100,003 spawns and stock, then stocks tabard 135,000 and returns verification rows.

## 1.2.3 — 2026-10-15

- Fixed the quartermaster hard reset so its temporary clone table is created inside the discovered world schema instead of the default auth schema.
- Added regression coverage so the scoped world account never needs temporary-table privileges on auth.

## 1.2.2 — 2026-10-15

- Fixed the quartermaster bridge on repacks where the signup account can read `world.creature` but cannot see its columns through `information_schema.COLUMNS`.
- The bridge now discovers the creature entry column from a zero-row query against the spawn table itself, without reading or changing any spawn data.
- Added regression coverage for both `id` and `id1` creature-entry column layouts.

## 1.2.1 — 2026-10-15

- Fixed the quartermaster inspection route so a database error is returned as JSON instead of sending headers too early and collapsing into a Cloudflare 502.
- Removed the baked-in bridge-token hash fallback; the bridge is now disabled unless `WORLD_BRIDGE_TOKEN_SHA256` is explicitly configured.

## 1.2.0 — 2026-10-15

- Added an authenticated, fixed-operation bridge for inspecting the BuckmanHoldings quartermaster donor, custom template, spawn rows, and vendor stock.
- Added a transaction-protected hard reset that deletes every spawn of creature 9,100,002, replaces only that custom template with a clean clone of visible donor 59,908, and restores tabard 135,000 to its vendor stock.
- The bridge is not an arbitrary SQL endpoint: table names, IDs, columns, and statements are fixed in code.
- Added bearer-token authentication using a stored SHA-256 hash and constant-time comparison.
- Added automated coverage for bridge authentication and fixed target IDs.

## 1.1.0 — 2026-10-15

- Fixed the wardrobe item-slot routing oops: realm lookups now use WoW `InventoryType` and can only enter compatible slots.
- A tabard lookup now moves to Tabard instead of remaining in whichever slot was selected.
- Rings and trinkets choose the selected compatible slot or the first empty matching slot.
- Existing filled slots are never silently overwritten.
- Unknown or non-equippable inventory types are rejected instead of being misplaced.
- Added a visible wardrobe version button with the current release note.
- Corrected the default set title to `Blessings of Willa Rose`.
- Added automated coverage for slot routing and release identification.

## 1.0.0 — 2026-10-15

- Added the 19-slot MoP paper doll at `/wardrobe`.
- Added local browser persistence and JSON set export.
- Added read-only realm item lookup at `/wardrobe-item`.
- Added the Wardrobe footer link to the signup page.

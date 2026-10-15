# WoW Signup and Willa Rose Wardrobe changelog

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

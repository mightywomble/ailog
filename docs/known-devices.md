# Device Registry

Authoritative record of Tailscale devices in the network, their owners, and assigned tags.

## Board Devices

| Device ID | Hostname | Owner | Purpose | Tags | Registered |
|-----------|----------|-------|---------|------|-----------|
| 3078127046547774 | omarchym1 | Board | personal laptop | tag:board-device | 2026-11-17 |

## Documentation

Each device entry records:
- **Device ID**: Tailscale numeric ID
- **Hostname**: Device name in Tailscale
- **Owner**: Individual or role (e.g., Board)
- **Purpose**: What the device is used for
- **Tags**: Assigned Tailscale access tags
- **Registered**: Date added to the registry

This registry is the source of truth for device ownership and is checked daily by SAF-136.

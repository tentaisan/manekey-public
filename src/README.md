# Shared Implementation

This directory provides the board-independent authentication implementation.
Hardware access and firmware memory placement belong to the ports.

| Component | Responsibility |
| --- | --- |
| `ctaphid/` | CTAPHID, FIDO commands, PIN/UV, credentials, crypto interfaces and storage contracts |
| `frontend/` | Transport-facing request handling and ingress arbitration |
| `transport/` | USB, BLE and internal interconnect adapters |
| `boundary/` | Trusted backend gateways, mailboxes and isolation interfaces |
| `presence/`, `presence.rs` | User-presence interfaces and policies |
| `user_interface.rs` | Presence indication and UI contracts |
| `security.rs` | Shared security support |
| `paired_journal.rs`, `storage_region.rs` | Journal and storage-region support |
| `lib.rs` | Library entry point and feature selection |

Frontends translate transport traffic into shared protocol requests.
Boundary adapters connect requests to trusted services; ports supply the
hardware, storage and cryptographic providers. An interface alone does not
establish hardware isolation.

## Boundary models

| Model | Role |
| --- | --- |
| Direct | Frontend and trusted services share an execution environment |
| Task or core separation | Requests cross a local mailbox between execution contexts |
| MPU / PMP | Selected ports restrict CPU memory access around a trusted service |
| TrustZone | Selected ports connect Secure services to Non-Secure frontends through gateways |

Frontends submit requests and receive responses; trusted backends own
authentication state and key/storage operations. Ports assign the actual
memory, execution privilege and peripheral ownership. Mailboxes and gateways
define the interface but do not, by themselves, enforce hardware protection.

Task/core separation is not a security boundary against arbitrary memory
access. MPU/PMP protect configured CPU accesses; DMA and interrupt ownership
require additional port-specific handling. TrustZone peripheral and controller
placement is likewise configuration-dependent. Do not infer whole-system
isolation from the presence of a boundary feature.

Build a concrete implementation using its port README. Features are selected
by the consuming port rather than by a separate firmware in this directory.

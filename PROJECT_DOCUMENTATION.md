# SecurePhone: Intelligent Mobile Security and Anti-Theft Platform

**Tagline:** *Protect. Locate. Recover.*

---

## Abstract

Mobile devices have become indispensable repositories of personal, financial, and professional data, making smartphone loss and theft a critical security concern worldwide. When a device is stolen, perpetrators frequently power down the device immediately to sever network connectivity and prevent location tracking. Furthermore, victims often face fragmented processes when reporting missing devices, coordinating with finders, and tracking recovery progress.

**SecurePhone** is a web-based intelligent mobile security and anti-theft platform designed to address these challenges through a centralized, user-friendly system. Built using **HTML, CSS, and JavaScript** on the frontend, **Python Flask** on the backend, **SQLite** for relational data persistence, and **Leaflet with OpenStreetMap** for geospatial visualization, SecurePhone integrates proactive security awareness with reactive recovery workflows. Key features include an interactive visual phone mockup demonstrating **Shutdown-Authentication Simulation** (requiring PIN/Passcode verification before permitting power-off), **permission-based browser location sharing**, **Lost Mode activation and theft reporting** with unique recovery case numbers, a **public Found-Device reporting portal** coupled with an automated **Lost-and-Found matching engine**, and dedicated **Owner and Administrator dashboards**. By combining preventative security concepts with structured recovery case management, SecurePhone provides a practical prototype and extensible foundation for modern mobile anti-theft systems.

---

## 1. Introduction

### 1.1 Background
The proliferation of smartphones has transformed daily communication, commerce, and identity management. However, the high monetary and informational value of mobile devices makes them prime targets for theft and accidental loss. Traditional recovery tools focus primarily on passive GPS tracking, which becomes ineffective the moment a thief powers off the device, enables airplane mode, or removes the SIM card. Additionally, even when a lost device is discovered by a Good Samaritan or recovered by authorities, the lack of a unified matching and case-tracking registry frequently prevents the device from being reunited with its rightful owner.

### 1.2 Problem Statement
1. **Immediate Power-Off Vulnerability:** Most mobile operating systems allow an unauthenticated user to hold the physical power button and shut down the device from the lock screen, immediately disabling GPS and network tracking.
2. **Fragmented Reporting & Tracking:** Device owners lack a single platform to register device identifiers (such as IMEI and serial numbers), file structured theft reports, and track case statuses from initial loss to final recovery.
3. **Disconnected Lost-and-Found Ecosystem:** Individuals who find misplaced devices often have no safe, structured way to report found hardware attributes so they can be cross-referenced against active missing-device reports.
4. **Privacy Concerns in Location Tracking:** Continuous, non-consensual background tracking raises privacy issues; users need transparent, permission-based location sharing that they can toggle on or off at will.

### 1.3 Project Objectives
- **Design and implement a centralized web platform** for mobile device registration, security simulation, theft reporting, and recovery coordination.
- **Demonstrate Shutdown-Authentication concepts** via an interactive web-based smartphone mockup that requires secondary authentication (PIN/Password) before permitting device shutdown.
- **Implement permission-based geospatial tracking** using the browser Geolocation API, Leaflet.js, and OpenStreetMap to record and visualize device coordinates only with explicit user consent.
- **Automate Lost-and-Found correlation** by matching reported missing devices against public or authenticated found-device submissions using IMEI, brand, model, color, and location proximity.
- **Enforce security best practices**, including password hashing, session-based authentication, role-based access control (Owner vs. Administrator), and server-side input validation.

### 1.4 Scope and Limitations
**Simulation Boundary:** Because SecurePhone operates as a web application running within standard browser sandboxes, the **Shutdown-Authentication Simulation** is an educational and functional UI prototype. It demonstrates the workflow and security logic of pre-shutdown verification on an interactive virtual handset rather than overriding hardware power buttons at the native OS kernel level.

---

## 2. System Analysis and Requirements

### 2.1 Existing vs. Proposed System

| Dimension | Existing Approaches | Proposed SecurePhone Platform |
| :--- | :--- | :--- |
| **Shutdown Prevention** | Standard lock screens often allow power-off without authentication, severing tracking immediately. | Interactive **Shutdown-Authentication Simulation** demonstrating mandatory PIN/Passcode verification prior to shutdown. |
| **Location Privacy** | Always-on background telemetry or opaque third-party tracking apps. | **Permission-based browser location sharing** with explicit user consent and clear active/inactive status indicators. |
| **Recovery Workflow** | Disconnected police reports, carrier blacklists, and informal social media posts. | **End-to-end Recovery Case Tracking** with unique case IDs (`SP-YYYY-XXXX`), status timelines, and admin verification. |
| **Finder Coordination** | No standardized matching between people who find phones and owners who lost them. | **Automated Lost-and-Found Matching Module** with public found-device reporting and multi-attribute similarity scoring. |

### 2.2 Functional Requirements

1. **User Authentication & Role Management**
   - Users can register as Device Owners and log in securely.
   - Pre-seeded **Demo Accounts** (Owner and Administrator) allow immediate evaluation of all platform workflows.
   - Role-Based Access Control (RBAC) separates Owner operations from Administrator oversight.
2. **Device Registration & Management**
   - Owners can register multiple mobile devices with Device Name, Brand, Model, IMEI/Serial Number, Color, Operating System, and a Shutdown Security PIN.
3. **Interactive Shutdown-Authentication Simulation**
   - A visual smartphone mockup displays lock-screen status, battery/network indicators, and a power-button trigger.
   - Attempting to power off prompts the user for their device's Shutdown PIN/Password.
   - Valid credentials trigger a simulated graceful shutdown; invalid attempts log a failed security event and keep the device online and trackable.
4. **Permission-Based Location Sharing**
   - Owners can explicitly grant or revoke browser geolocation access for a selected device.
   - Active sharing records latitude, longitude, accuracy, and timestamp, rendering an interactive marker and accuracy radius on a **Leaflet + OpenStreetMap** view.
5. **Lost Mode & Theft Reporting**
   - Owners can toggle **Lost Mode** (displaying a custom lock-screen recovery message on the simulated device) and submit a formal theft/loss report.
   - Submitting a report generates a unique **Recovery Case Number** and sets the case status to `Reported`.
6. **Public Found-Device Reporting & Lost-and-Found Matching**
   - Both unauthenticated Good Samaritans (public portal) and logged-in users can submit **Found Device Reports** specifying brand, model, color, partial/full IMEI (if visible), found location, and finder contact info.
   - The backend matching engine compares found reports against active lost reports and flags high-confidence and partial matches for review.
7. **Owner & Administrator Dashboards**
   - **Owner Dashboard:** Overview of registered devices, live location map, active recovery cases, shutdown simulation logs, and potential match notifications.
   - **Administrator Dashboard:** System-wide metrics, all theft/loss reports, found-device submissions, match verification controls (`Verify Match`, `Reject Match`), and recovery case status management (`Reported` -> `Under Investigation` -> `Match Found` -> `Verified` -> `Recovered` / `Closed`).

### 2.3 Non-Functional Requirements
- **Security:** Passwords hashed using Werkzeug/PBKDF2-SHA256; CSRF/session protection; parameterized SQL queries preventing SQL injection; input sanitization preventing XSS.
- **Usability:** Responsive, modern dark/light cybersecurity-themed interface intuitive for both non-technical device owners and system administrators.
- **Reliability & Portability:** Zero-configuration SQLite database with automatic schema initialization and demo data seeding on startup.

### 2.4 Hardware and Software Requirements
- **Frontend:** HTML5, CSS3 (Custom Properties, Flexbox/Grid), Vanilla JavaScript (ES6+), Leaflet.js v1.9+, OpenStreetMap tile layer.
- **Backend:** Python 3.9+, Flask web framework (`Flask`, `Werkzeug`).
- **Database:** SQLite 3.
- **Client Environment:** Any modern web browser (Chrome, Edge, Firefox, Safari) with Geolocation API support.

---

## 3. System Architecture and Design

### 3.1 Three-Tier Architecture
SecurePhone follows a modular three-tier web architecture separating presentation, business logic, and data persistence:
- **Presentation Tier (Browser):** HTML5/CSS3/JS Interface, Interactive Phone Mockup (Shutdown Sim), Leaflet.js + OpenStreetMap, Browser Geolocation API.
- **Application Tier (Python Flask):** Session & RBAC Middleware, Device & Simulation Controller, Location Service Controller, Lost Mode & Recovery Case Controller, Lost-and-Found Matching Engine, Admin Verification Controller.
- **Data Tier (SQLite):** `securephone.db` relational database.

### 3.2 Database Schema Summary
- **`users`**: `id`, `full_name`, `email`, `phone_number`, `password_hash`, `role` (`owner` | `admin`), `created_at`
- **`devices`**: `id`, `user_id`, `device_name`, `brand`, `model`, `imei`, `color`, `os_version`, `shutdown_pin_hash`, `shutdown_auth_enabled`, `location_sharing_enabled`, `is_lost_mode`, `lock_screen_message`, `status`, `last_seen_at`
- **`location_logs`**: `id`, `device_id`, `latitude`, `longitude`, `accuracy`, `address_hint`, `recorded_at`
- **`shutdown_logs`**: `id`, `device_id`, `event_type` (`SUCCESS` | `FAILED_PIN` | `BLOCKED_LOST_MODE`), `ip_address`, `details`, `created_at`
- **`recovery_cases`**: `id`, `case_number`, `device_id`, `user_id`, `incident_type`, `incident_date`, `last_known_location`, `last_lat`, `last_lng`, `description`, `status`, `admin_notes`, `created_at`, `updated_at`
- **`found_reports`**: `id`, `reported_by_user_id`, `finder_name`, `finder_contact`, `brand`, `model`, `color`, `imei_partial`, `found_location`, `found_lat`, `found_lng`, `description`, `status`, `created_at`
- **`device_matches`**: `id`, `case_id`, `found_report_id`, `match_score`, `match_reasons`, `verification_status`, `created_at`

---

## 4. Core Module Specifications

### 4.1 Module 1: Interactive Shutdown-Authentication Simulation
- **Purpose:** Educate users and demonstrate how requiring a PIN/Passcode before powering down a mobile device prevents thieves from immediately severing tracking.
- **Interactive Phone Mockup:**
  - Displays a realistic smartphone frame showing time, carrier signal, GPS status badge, Lost Mode banner (if active), and a physical side **Power Button**.
  - When the user clicks **Power Off**, the mockup intercepts the shutdown sequence and renders a **Shutdown Security Prompt**.
  - **Verification Logic:**
    - If the entered PIN matches the device's configured Shutdown PIN, the mockup transitions to a powered-off state and records a `SUCCESS` audit event.
    - If the entered PIN is incorrect, the shutdown is blocked, an alert is triggered, and a `FAILED_PIN` event (with timestamp) is logged to the Owner Dashboard, simulating an anti-theft alert.

### 4.2 Module 2: Permission-Based Location Sharing
- **Purpose:** Provide transparent, consent-driven location tracking using web standards.
- **Mechanism:**
  - Uses `navigator.geolocation.getCurrentPosition()` and `watchPosition()` only when the owner explicitly switches **"Location Sharing Permission"** to `ON`.
  - Plots the device's last recorded coordinates on an interactive **Leaflet + OpenStreetMap** canvas with custom status pins (Green for Active, Red pulsing for Lost Mode).
  - Includes a built-in **"Simulate GPS Movement / Fallback Coordinates"** option so evaluators testing on desktop PCs without hardware GPS can test real-time coordinate updates seamlessly.

### 4.3 Module 3: Lost Mode & Theft Reporting
- **Purpose:** Centralize rapid response when a device goes missing.
- **Capabilities:**
  - **One-Click Lost Mode:** Locks the simulated handset, displays a high-visibility recovery message and emergency callback number on the virtual lock screen, and forces Shutdown Authentication on.
  - **Theft Report Generation:** Captures incident type (`Lost` vs. `Stolen`), date/time, last known location, and narrative description.
  - **Unique Case Identifier:** Automatically generates a structured tracking ID (e.g., `SP-2026-4821`) and initializes a step-by-step recovery timeline.

### 4.4 Module 4: Lost-and-Found Matching Engine
- **Purpose:** Bridge the gap between missing device reports and found hardware submissions.
- **Public & Authenticated Found Portal:** Allows any user or Good Samaritan to report a found phone without needing an owner account.
- **Multi-Factor Scoring Algorithm (0–100 Points):**
  Every time a Lost Case or Found Report is created, the engine evaluates pairs across four weighted criteria:
  1. **IMEI / Serial Match (Up to 50 pts):** Exact IMEI match awards 50 points; matching last 4–6 digits awards 35 points.
  2. **Brand & Model Similarity (Up to 25 pts):** Exact brand + model match awards 25 points; brand-only match awards 10 points.
  3. **Color Match (Up to 15 pts):** Case-insensitive color match awards 15 points.
  4. **Location / Description Keyword Overlap (Up to 10 pts):** Proximity of coordinates or shared location landmarks awards up to 10 points.
  - Pairs scoring >= 40 points are automatically recorded in `device_matches` with detailed `match_reasons` for Administrator verification and Owner visibility.

### 4.5 Module 5: Owner and Administrator Dashboards
- **Owner Dashboard:** Summary cards, Device Registry with quick actions, Live Leaflet map, Recovery Case tracker, and Security Event Log.
- **Administrator Dashboard:** Platform-wide KPIs, Match Verification Queue (`Verify Match` / `Reject`), and Case Management Table allowing status transitions and official administrator notes.

---

## 5. Security and Privacy Architecture

1. **Password & PIN Cryptography:** User passwords and device Shutdown PINs are salted and hashed using `werkzeug.security.generate_password_hash`.
2. **Session-Based Authentication & RBAC:** Route protection decorators (`@login_required`, `@admin_required`) prevent unauthorized access and enforce strict owner data isolation.
3. **Consent-First Geolocation:** Location coordinates are only captured when both browser permission is granted and the in-app sharing toggle is active.
4. **SQL Injection & XSS Mitigation:** Parameterized SQLite queries (`?`) and Jinja2 template auto-escaping protect against injection attacks.

---

## 6. Testing and Evaluation Plan

| Test ID | Feature Tested | Test Procedure | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-01** | Device Registration | Log in as Owner, submit a new device with 15-digit IMEI and 4-digit Shutdown PIN. | Device is saved in SQLite and appears on the Owner Dashboard. |
| **TC-02** | Shutdown Auth Block | Open Shutdown Simulator, click Power Off, and enter an incorrect PIN (`0000`). | Shutdown is denied; phone remains online; `FAILED_PIN` event is logged. |
| **TC-03** | Shutdown Auth Success | Open Shutdown Simulator, click Power Off, and enter the valid PIN (`1234`). | Simulated phone powers down gracefully; `SUCCESS` event is logged. |
| **TC-04** | Permission Location Sharing | Enable Location Sharing on a device and click "Update Current Location". | Browser prompts for permission; Leaflet map updates marker & timestamp. |
| **TC-05** | Lost Mode & Case Generation | Activate Lost Mode and submit a Theft Report for a registered device. | Device status changes to `Lost`; unique Case ID (`SP-2026-XXXX`) is generated. |
| **TC-06** | Public Found Report & Auto-Match | Submit a public Found Device Report matching the brand, model, and color of a lost phone. | Matching engine calculates score (>= 40%) and creates a `Pending` match record. |
| **TC-07** | Admin Match Verification | Log in as Admin, review the flagged match, and click **Verify Match**. | Match status updates to `Verified`; Recovery Case advances to `Match Found` / `Verified`. |

---

## 7. Conclusion and Future Enhancements

### 7.1 Conclusion
**SecurePhone** demonstrates how a cohesive web platform can bridge preventative mobile security education with structured post-theft recovery management. By combining an interactive Shutdown-Authentication simulation, consent-based Leaflet mapping, automated lost-and-found correlation, and role-based case tracking, the prototype fulfills its mission: **Protect. Locate. Recover.**

### 7.2 Future Enhancements
- **Native Mobile Companion App (Android/iOS):** Utilizing Android Accessibility/Device Admin APIs to enforce lock-screen power-menu authentication on physical hardware.
- **Automated Photo & Audio Capture:** Capturing front-camera snapshots upon repeated failed shutdown PIN attempts.
- **Carrier & Law Enforcement API Integration:** Direct CEIR/IMEI blacklist submission and automated PDF police report generation.
- **QR-Code Digital Recovery Tags:** Generating printable lock-screen QR wallpapers that let finders scan and message the owner anonymously without unlocking the phone.

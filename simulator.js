/**
 * Feature A: Shutdown Authentication Protection — Interactive Virtual Smartphone Controller
 * Implements press-and-hold / click power button, shutdown confirmation, demo PIN & biometric
 * verification, simulated shutdown animation, "Device Powered Off (Simulation)" screen,
 * virtual phone restart, and real-time Security Event Log with live counters.
 * Never collects or stores real device PINs, passwords, or biometric credentials.
 */

document.addEventListener("DOMContentLoaded", () => {
  const chassis = document.getElementById("phone-chassis");
  const powerBtn = document.getElementById("sim-power-btn");
  const altPowerBtn = document.getElementById("sim-trigger-power-btn");
  const holdFill = document.getElementById("sim-power-hold-fill");

  const confirmOverlay = document.getElementById("sim-confirm-overlay");
  const authOverlay = document.getElementById("sim-auth-overlay");
  const shutdownAnimOverlay = document.getElementById("sim-shutdown-anim-overlay");
  const shutdownAnimBar = document.getElementById("sim-shutdown-anim-bar");
  const resultOverlay = document.getElementById("sim-result-overlay");
  const poweredOffOverlay = document.getElementById("sim-powered-off-overlay");

  const proceedToAuthBtn = document.getElementById("sim-proceed-auth-btn");
  const cancelConfirmBtn = document.getElementById("sim-cancel-confirm-btn");
  const cancelAuthBtn = document.getElementById("sim-cancel-auth-btn");
  const retryBtn = document.getElementById("sim-retry-btn");
  const rebootBtn = document.getElementById("sim-reset-btn");
  const restartPhoneBtn = document.getElementById("sim-restart-phone-btn");

  const pinInput = document.getElementById("sim-demo-pin-input");
  const fillValidPinBtn = document.getElementById("sim-fill-valid-pin");
  const fillWrongPinBtn = document.getElementById("sim-fill-wrong-pin");
  const authErrorMsg = document.getElementById("sim-auth-error-msg");
  const verifyPinBtn = document.getElementById("sim-verify-pin-btn");
  const bioPassBtn = document.getElementById("sim-bio-pass-btn");
  const bioFailBtn = document.getElementById("sim-bio-fail-btn");

  const resultBadge = document.getElementById("sim-result-badge");
  const resultTitle = document.getElementById("sim-result-title");
  const resultDesc = document.getElementById("sim-result-desc");
  const poweredOffDesc = document.getElementById("sim-powered-off-desc");

  const eventLogBody = document.getElementById("sim-event-log-body");
  const clearLogBtn = document.getElementById("sim-clear-log-btn");
  const clockTimeEl = document.getElementById("sim-clock-time");
  const networkStatusEl = document.getElementById("sim-network-status");

  const countTotalEl = document.getElementById("sim-count-total");
  const countSuccessEl = document.getElementById("sim-count-success");
  const countFailedEl = document.getElementById("sim-count-failed");
  const countCancelledEl = document.getElementById("sim-count-cancelled");

  // Quick Scenario Test Buttons
  const quickOpenPowerBtn = document.getElementById("sim-quick-open-power");
  const quickTestFailBtn = document.getElementById("sim-quick-test-fail");
  const quickTestPassBtn = document.getElementById("sim-quick-test-pass");
  const quickRestartBtn = document.getElementById("sim-quick-restart");

  if (!powerBtn || !chassis) return;

  const expectedPin = chassis.getAttribute("data-expected-pin") || "2580";
  const deviceLabel = chassis.getAttribute("data-device-label") || "Public Demo Virtual Handset";
  let isPoweredOff = false;
  let holdTimer = null;
  let holdProgress = 0;

  let stats = {
    total: 0,
    success: 0,
    failed: 0,
    cancelled: 0
  };

  function initCountersFromDOM() {
    if (!eventLogBody) return;
    const rows = eventLogBody.querySelectorAll("tr[data-outcome]");
    rows.forEach((r) => {
      const outcome = r.getAttribute("data-outcome");
      stats.total += 1;
      if (outcome === "SUCCESS") stats.success += 1;
      else if (outcome === "FAILED") stats.failed += 1;
      else if (outcome === "CANCELLED") stats.cancelled += 1;
    });
    renderCounters();
  }

  function renderCounters() {
    if (countTotalEl) countTotalEl.textContent = String(stats.total);
    if (countSuccessEl) countSuccessEl.textContent = String(stats.success);
    if (countFailedEl) countFailedEl.textContent = String(stats.failed);
    if (countCancelledEl) countCancelledEl.textContent = String(stats.cancelled);
  }

  initCountersFromDOM();

  function formatNowLocal() {
    const now = new Date();
    return now.toLocaleString("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    }) + " IST";
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function appendSecurityLogRow(timestamp, methodLabel, outcome, details) {
    if (!eventLogBody) return;
    const emptyRow = eventLogBody.querySelector(".empty-log-row");
    if (emptyRow) emptyRow.remove();

    stats.total += 1;
    let badgeClass = "badge-info";
    let badgeText = outcome;
    if (outcome === "SUCCESS" || outcome === "AUTHORIZED") {
      stats.success += 1;
      badgeClass = "badge-protected";
      badgeText = "VERIFIED (SUCCESS)";
    } else if (outcome === "FAILED" || outcome === "BLOCKED") {
      stats.failed += 1;
      badgeClass = "badge-lost";
      badgeText = "FAILED (BLOCKED)";
    } else if (outcome === "CANCELLED") {
      stats.cancelled += 1;
      badgeClass = "badge-warning";
      badgeText = "CANCELLED";
    } else if (outcome === "RESTARTED") {
      badgeClass = "badge-info";
      badgeText = "PHONE RESTARTED";
    } else if (outcome === "ATTEMPT") {
      badgeClass = "badge-info";
      badgeText = "POWER MENU";
    }
    renderCounters();

    const tr = document.createElement("tr");
    tr.setAttribute("data-outcome", outcome);
    tr.innerHTML = `
      <td><code>${escapeHtml(timestamp || formatNowLocal())}</code></td>
      <td><span class="badge badge-info">${escapeHtml(methodLabel)}</span></td>
      <td><span class="badge ${badgeClass}">${escapeHtml(badgeText)}</span></td>
      <td>${escapeHtml(details)}</td>
    `;
    eventLogBody.prepend(tr);
  }

  function updateClock() {
    if (!clockTimeEl) return;
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    clockTimeEl.textContent = `${hh}:${mm}`;
  }
  updateClock();
  setInterval(updateClock, 15000);

  function resetChassisGlow() {
    chassis.classList.remove("sim-state-success", "sim-state-blocked", "sim-state-powered-off");
  }

  function hideAllOverlays() {
    confirmOverlay.classList.add("hidden");
    authOverlay.classList.add("hidden");
    if (shutdownAnimOverlay) shutdownAnimOverlay.classList.add("hidden");
    resultOverlay.classList.add("hidden");
    if (poweredOffOverlay) poweredOffOverlay.classList.add("hidden");
  }

  function showInlineAuthError(msg) {
    if (!authErrorMsg) return;
    if (!msg) {
      authErrorMsg.classList.add("hidden");
      authErrorMsg.textContent = "";
    } else {
      authErrorMsg.textContent = msg;
      authErrorMsg.classList.remove("hidden");
    }
  }

  function openShutdownConfirmation(logTrigger = true) {
    if (isPoweredOff) {
      window.SecurePhoneUI.showToast("Virtual phone is powered off. Click 'Restart Virtual Phone' first.", "info");
      return;
    }
    resetChassisGlow();
    hideAllOverlays();
    confirmOverlay.classList.remove("hidden");
    if (holdFill) holdFill.style.width = "0%";
    if (logTrigger) {
      notifyServerEvent({ method: "power_hold" })
        .then((data) => {
          appendSecurityLogRow(
            data.timestamp_local || formatNowLocal(),
            "POWER BUTTON",
            "ATTEMPT",
            data.message || `Power button held on ${deviceLabel}. Shutdown confirmation screen displayed.`
          );
        })
        .catch(() => {
          appendSecurityLogRow(
            formatNowLocal(),
            "POWER BUTTON",
            "ATTEMPT",
            `Power button held on ${deviceLabel}. Shutdown confirmation screen displayed.`
          );
        });
    }
  }

  function openAuthScreen(retryWarning = "") {
    resetChassisGlow();
    hideAllOverlays();
    if (pinInput) pinInput.value = "";
    showInlineAuthError(retryWarning);
    authOverlay.classList.remove("hidden");
    if (pinInput) pinInput.focus();
  }

  // Press-and-Hold animation + Click support on Virtual Power Buttons
  function startPowerHold() {
    if (isPoweredOff) return;
    clearInterval(holdTimer);
    holdProgress = 25;
    if (holdFill) holdFill.style.width = `${holdProgress}%`;
    holdTimer = setInterval(() => {
      holdProgress += 25;
      if (holdFill) holdFill.style.width = `${Math.min(holdProgress, 100)}%`;
      if (holdProgress >= 100) {
        clearInterval(holdTimer);
        holdTimer = null;
        openShutdownConfirmation(true);
      }
    }, 90);
  }

  function endPowerHold() {
    if (holdTimer) {
      clearInterval(holdTimer);
      holdTimer = null;
      if (holdFill) holdFill.style.width = "0%";
    }
  }

  [powerBtn, altPowerBtn].forEach((btn) => {
    if (!btn) return;
    btn.addEventListener("mousedown", startPowerHold);
    btn.addEventListener("mouseup", endPowerHold);
    btn.addEventListener("mouseleave", endPowerHold);
    btn.addEventListener("touchstart", startPowerHold, { passive: true });
    btn.addEventListener("touchend", endPowerHold);
    btn.addEventListener("click", () => {
      endPowerHold();
      if (confirmOverlay.classList.contains("hidden") && authOverlay.classList.contains("hidden") && !isPoweredOff) {
        openShutdownConfirmation(true);
      }
    });
  });

  async function notifyServerEvent(payload) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
    const deviceSelect = document.getElementById("sim-device-select");
    const deviceId = deviceSelect ? deviceSelect.value : null;

    const res = await fetch("/api/simulator/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken
      },
      body: JSON.stringify({
        ...payload,
        device_id: deviceId ? parseInt(deviceId, 10) : null,
        csrf_token: csrfToken
      })
    });
    return await res.json();
  }

  async function handleCancelShutdown(stageName) {
    resetChassisGlow();
    hideAllOverlays();
    showInlineAuthError("");
    try {
      const data = await notifyServerEvent({ method: "cancel", stage: stageName });
      appendSecurityLogRow(
        data.timestamp_local || formatNowLocal(),
        "CANCEL",
        "CANCELLED",
        data.message || `Shutdown cancelled at ${stageName}. Virtual handset remains ON.`
      );
    } catch (_err) {
      appendSecurityLogRow(
        formatNowLocal(),
        "CANCEL",
        "CANCELLED",
        `Shutdown cancelled at ${stageName}. Virtual handset remains ON.`
      );
    }
    window.SecurePhoneUI.showToast("Simulated shutdown cancelled. Virtual phone remains active.", "info");
  }

  if (cancelConfirmBtn) {
    cancelConfirmBtn.addEventListener("click", () => handleCancelShutdown("Confirmation Menu"));
  }

  if (proceedToAuthBtn) {
    proceedToAuthBtn.addEventListener("click", () => openAuthScreen(""));
  }

  if (cancelAuthBtn) {
    cancelAuthBtn.addEventListener("click", () => handleCancelShutdown("Security Verification"));
  }

  if (fillValidPinBtn && pinInput) {
    fillValidPinBtn.addEventListener("click", () => {
      pinInput.value = expectedPin;
      showInlineAuthError("");
    });
  }

  if (fillWrongPinBtn && pinInput) {
    fillWrongPinBtn.addEventListener("click", () => {
      pinInput.value = "0000";
      showInlineAuthError("");
    });
  }

  document.querySelectorAll(".pin-key[data-digit]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const digit = btn.getAttribute("data-digit");
      showInlineAuthError("");
      if (digit === "clear") {
        pinInput.value = "";
      } else if (digit === "back") {
        pinInput.value = pinInput.value.slice(0, -1);
      } else if (pinInput.value.length < 6) {
        pinInput.value += digit;
      }
    });
  });

  if (pinInput) {
    pinInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        if (verifyPinBtn) verifyPinBtn.click();
      }
    });
  }

  function showPoweredOffSimulationScreen(message) {
    hideAllOverlays();
    resetChassisGlow();
    isPoweredOff = true;
    chassis.classList.add("sim-state-success", "sim-state-powered-off");
    if (networkStatusEl) networkStatusEl.textContent = "OFFLINE (SIMULATED)";
    if (poweredOffDesc && message) {
      poweredOffDesc.textContent = message;
    }
    if (poweredOffOverlay) {
      poweredOffOverlay.classList.remove("hidden");
    } else {
      resultOverlay.classList.remove("hidden");
    }
  }

  async function submitVerification(payload) {
    try {
      const data = await notifyServerEvent(payload);
      hideAllOverlays();
      resetChassisGlow();

      const timeStr = data.timestamp_local || data.timestamp || formatNowLocal();
      const methodLabel = (data.method || payload.method || "pin").toUpperCase();

      if (data.authorized) {
        appendSecurityLogRow(timeStr, methodLabel, "SUCCESS", data.message);
        window.SecurePhoneUI.showToast("Identity verified! Running simulated shutdown...", "success");

        // Play smooth simulated shutdown animation before showing "Device Powered Off (Simulation)"
        if (shutdownAnimOverlay && shutdownAnimBar) {
          shutdownAnimOverlay.classList.remove("hidden");
          shutdownAnimBar.style.width = "0%";
          requestAnimationFrame(() => {
            shutdownAnimBar.style.width = "100%";
          });
          setTimeout(() => {
            showPoweredOffSimulationScreen(data.message);
          }, 750);
        } else {
          showPoweredOffSimulationScreen(data.message);
        }
      } else {
        isPoweredOff = false;
        chassis.classList.add("sim-state-blocked");
        resultOverlay.classList.remove("hidden");
        resultBadge.className = "badge badge-lost";
        resultBadge.textContent = "SHUTDOWN BLOCKED (ANTI-THEFT ACTIVE)";
        resultTitle.textContent = "Verification Failed — Shutdown Prevented";
        resultDesc.textContent = data.message;
        retryBtn.classList.remove("hidden");

        appendSecurityLogRow(timeStr, methodLabel, "FAILED", data.message);
        window.SecurePhoneUI.showToast("Verification failed! Simulated shutdown prevented.", "error");
      }
    } catch (_err) {
      window.SecurePhoneUI.showToast("Network error during simulation check.", "error");
    }
  }

  if (verifyPinBtn) {
    verifyPinBtn.addEventListener("click", () => {
      const val = (pinInput ? pinInput.value : "").trim();
      if (!val) {
        showInlineAuthError("Please enter the Demo PIN (or click Auto-Fill) before verifying.");
        return;
      }
      submitVerification({ method: "pin", pin: val });
    });
  }

  if (bioPassBtn) {
    bioPassBtn.addEventListener("click", () => {
      submitVerification({ method: "biometric", biometric_outcome: "pass" });
    });
  }

  if (bioFailBtn) {
    bioFailBtn.addEventListener("click", () => {
      submitVerification({ method: "biometric", biometric_outcome: "fail" });
    });
  }

  if (retryBtn) {
    retryBtn.addEventListener("click", () => {
      openAuthScreen("Previous verification failed. Enter the authorized Demo PIN to retry.");
    });
  }

  if (rebootBtn) {
    rebootBtn.addEventListener("click", () => handleCancelShutdown("Blocked Alert Screen"));
  }

  async function restartVirtualPhone() {
    isPoweredOff = false;
    resetChassisGlow();
    hideAllOverlays();
    showInlineAuthError("");
    if (networkStatusEl) networkStatusEl.textContent = "SmartCity 5G \u2022 Protected";
    try {
      const data = await notifyServerEvent({ method: "restart" });
      appendSecurityLogRow(
        data.timestamp_local || formatNowLocal(),
        "RESTART",
        "RESTARTED",
        data.message || `Virtual smartphone (${deviceLabel}) restarted and returned to lock screen.`
      );
    } catch (_err) {
      appendSecurityLogRow(
        formatNowLocal(),
        "RESTART",
        "RESTARTED",
        `Virtual smartphone (${deviceLabel}) restarted and returned to lock screen.`
      );
    }
    window.SecurePhoneUI.showToast("Virtual phone restarted and ready on lock screen.", "info");
  }

  if (restartPhoneBtn) {
    restartPhoneBtn.addEventListener("click", restartVirtualPhone);
  }

  // Quick Scenario Buttons in Right Column
  if (quickOpenPowerBtn) {
    quickOpenPowerBtn.addEventListener("click", () => {
      if (isPoweredOff) {
        restartVirtualPhone().then(() => openShutdownConfirmation(true));
      } else {
        openShutdownConfirmation(true);
      }
    });
  }

  if (quickTestFailBtn) {
    quickTestFailBtn.addEventListener("click", () => {
      isPoweredOff = false;
      submitVerification({ method: "pin", pin: "0000" });
    });
  }

  if (quickTestPassBtn) {
    quickTestPassBtn.addEventListener("click", () => {
      isPoweredOff = false;
      submitVerification({ method: "pin", pin: expectedPin });
    });
  }

  if (quickRestartBtn) {
    quickRestartBtn.addEventListener("click", restartVirtualPhone);
  }

  if (clearLogBtn && eventLogBody) {
    clearLogBtn.addEventListener("click", () => {
      stats = { total: 0, success: 0, failed: 0, cancelled: 0 };
      renderCounters();
      eventLogBody.innerHTML = `
        <tr class="empty-log-row">
          <td colspan="4" style="text-align:center; color:var(--text-muted);">
            Security event log cleared. Interact with the virtual smartphone to record new events.
          </td>
        </tr>
      `;
    });
  }
});

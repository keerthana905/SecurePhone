/**
 * Feature B: Permission-Based Location Sharing, Reverse Geocoding & Leaflet Map Controller
 * Resolves GPS coordinates into readable street addresses via OpenStreetMap Nominatim
 * (with coordinate caching, 1 req/sec rate-limit compliance, and backend fallback to
 * "Address unavailable"), displays local IST timestamps, and updates Trusted Contact SOS alerts.
 */

document.addEventListener("DOMContentLoaded", () => {
  const mapEl = document.getElementById("device-map");
  if (!mapEl) return;

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
  const deviceId = parseInt(mapEl.getAttribute("data-device-id") || "0", 10);
  const initialLat = parseFloat(mapEl.getAttribute("data-lat") || "12.9716");
  const initialLng = parseFloat(mapEl.getAttribute("data-lng") || "77.5946");
  const initialAcc = parseFloat(mapEl.getAttribute("data-accuracy") || "15");
  const hasSavedFix = mapEl.getAttribute("data-has-fix") === "true";
  const deviceName = mapEl.getAttribute("data-device-name") || "Registered Device";
  const initialAddress = mapEl.getAttribute("data-address") || "Address unavailable";
  const initialLocalTime = mapEl.getAttribute("data-local-time") || "No timestamp";
  let sharingEnabled = mapEl.getAttribute("data-sharing-enabled") === "true";
  let isLiveSessionFix = false;

  const statusBanner = document.getElementById("location-error-banner");
  const loadingIndicator = document.getElementById("address-loading-indicator");
  const enableBtn = document.getElementById("btn-enable-sharing");
  const stopBtn = document.getElementById("btn-stop-sharing");
  const browserFixBtn = document.getElementById("btn-browser-gps-fix");
  const demoFixBtn = document.getElementById("btn-demo-smartcity-fix");
  const testExampleCoordsBtn = document.getElementById("btn-test-example-coords");
  const sharingBadge = document.getElementById("sharing-status-badge");
  const freshnessBadge = document.getElementById("location-freshness-badge");
  const placeAddressEl = document.getElementById("place-address-display");
  const gpsDetailsEl = document.getElementById("gps-coords-details");
  const lastCoordsEl = document.getElementById("last-coords-display");
  const lastDmsEl = document.getElementById("last-dms-display");
  const lastTimeEl = document.getElementById("last-time-display");
  const lastAccuracyEl = document.getElementById("last-accuracy-display");
  const googleMapsLink = document.getElementById("link-google-maps");
  const osmMapLink = document.getElementById("link-osm-map");
  const historyBody = document.getElementById("location-history-body");

  const sosPreviewEl = document.getElementById("sos-alert-preview");
  const sosModeBadge = document.getElementById("sos-mode-badge");
  const sosContactInput = document.getElementById("sos-trusted-contact");
  const sendSosBtn = document.getElementById("btn-send-sos");
  const copySosBtn = document.getElementById("btn-copy-sos");

  // Client-side coordinate cache & rate-limit tracker for Nominatim (max 1 req/sec)
  const clientGeocodeCache = new Map();
  let lastNominatimRequestMs = 0;

  let map = null;
  let marker = null;
  let accuracyCircle = null;

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function buildPopupHtml(lat, lng, acc, address, localTime, isLive) {
    const modeTag = isLive ? "[LIVE LOCATION]" : "[LAST KNOWN LOCATION]";
    const gmapUrl = `https://www.google.com/maps?q=${lat.toFixed(6)},${lng.toFixed(6)}`;
    const osmUrl = `https://www.openstreetmap.org/?mlat=${lat.toFixed(6)}&mlon=${lng.toFixed(6)}#map=17/${lat.toFixed(6)}/${lng.toFixed(6)}`;
    return `
      <div style="min-width:220px; line-height:1.45;">
        <strong>${escapeHtml(deviceName)}</strong>
        <span style="display:inline-block; font-size:0.7rem; font-weight:700; padding:0.1rem 0.4rem; border-radius:4px; margin-left:0.25rem; background:${isLive ? "#55D6A7" : "#FFC766"}; color:#15121F;">
          ${modeTag}
        </span>
        <div style="margin-top:0.35rem; font-weight:600;">
          ${escapeHtml(address || "Address unavailable")}
        </div>
        <div style="margin-top:0.25rem; font-size:0.78rem; opacity:0.9;">
          Updated: ${escapeHtml(localTime)}<br>
          GPS: ${lat.toFixed(5)}, ${lng.toFixed(5)} (&plusmn;${Math.round(acc)} m)
        </div>
        <div style="margin-top:0.35rem; font-size:0.78rem;">
          <a href="${gmapUrl}" target="_blank" rel="noopener noreferrer">Google Maps &nearr;</a>
          &bull;
          <a href="${osmUrl}" target="_blank" rel="noopener noreferrer">OpenStreetMap &nearr;</a>
        </div>
      </div>
    `;
  }

  if (typeof L !== "undefined") {
    map = L.map("device-map").setView([initialLat, initialLng], hasSavedFix ? 15 : 12);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    if (hasSavedFix) {
      renderMapMarker(
        initialLat,
        initialLng,
        initialAcc,
        buildPopupHtml(initialLat, initialLng, initialAcc, initialAddress, initialLocalTime, false)
      );
    }
  }

  function renderMapMarker(lat, lng, acc, popupText) {
    if (!map || typeof L === "undefined") return;
    if (marker) map.removeLayer(marker);
    if (accuracyCircle) map.removeLayer(accuracyCircle);

    const cyberIcon = L.divIcon({
      className: "cyber-div-icon",
      html: '<div class="cyber-map-marker"></div>',
      iconSize: [26, 26],
      iconAnchor: [13, 26],
      popupAnchor: [0, -24]
    });

    marker = L.marker([lat, lng], { icon: cyberIcon }).addTo(map).bindPopup(popupText).openPopup();
    accuracyCircle = L.circle([lat, lng], {
      radius: Math.max(acc, 12),
      color: "#35E0CF",
      weight: 2,
      fillColor: "#9B7BFF",
      fillOpacity: 0.22
    }).addTo(map);
    map.setView([lat, lng], 15);
  }

  function formatNominatimAddress(data) {
    if (!data || typeof data !== "object") return null;
    const addr = data.address || {};
    const parts = [];

    function addPart(val) {
      if (!val) return;
      const text = String(val).trim();
      if (!text) return;
      const lower = text.toLowerCase();
      if (!parts.some((p) => p.toLowerCase() === lower)) {
        parts.push(text);
      }
    }

    const placeKeys = ["amenity", "building", "shop", "office", "tourism", "historic", "leisure", "railway", "aeroway"];
    if (data.name) addPart(data.name);
    for (const k of placeKeys) {
      if (addr[k]) {
        addPart(addr[k]);
        break;
      }
    }

    const house = String(addr.house_number || "").trim();
    const road = String(addr.road || addr.pedestrian || addr.footway || addr.street || "").trim();
    if (house && road) {
      addPart(`${house} ${road}`);
    } else if (road) {
      addPart(road);
    }

    for (const k of ["neighbourhood", "suburb", "quarter", "residential", "city_district", "borough"]) {
      if (addr[k]) addPart(addr[k]);
    }

    for (const k of ["city", "town", "village", "municipality", "county"]) {
      if (addr[k]) {
        addPart(addr[k]);
        break;
      }
    }

    for (const k of ["state", " state_district", "region", "province"]) {
      if (addr[k]) {
        addPart(addr[k]);
        break;
      }
    }

    if (addr.country) addPart(addr.country);
    if (addr.postcode) addPart(addr.postcode);

    if (parts.length > 0) {
      return parts.join(", ");
    }
    if (data.display_name && String(data.display_name).trim()) {
      return String(data.display_name).trim();
    }
    return null;
  }

  async function reverseGeocodeClient(lat, lng) {
    const cacheKey = `${lat.toFixed(4)},${lng.toFixed(4)}`;
    if (clientGeocodeCache.has(cacheKey)) {
      return clientGeocodeCache.get(cacheKey);
    }

    // Respect Nominatim 1 req/sec rate limit
    const elapsed = Date.now() - lastNominatimRequestMs;
    if (elapsed < 1050 && lastNominatimRequestMs > 0) {
      await new Promise((r) => setTimeout(r, 1050 - elapsed));
    }
    lastNominatimRequestMs = Date.now();

    try {
      const url = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${encodeURIComponent(lat.toFixed(6))}&lon=${encodeURIComponent(lng.toFixed(6))}&addressdetails=1&zoom=18&accept-language=en`;
      const res = await fetch(url, {
        headers: { Accept: "application/json" }
      });
      if (!res.ok) return null;
      const payload = await res.json();
      const formatted = formatNominatimAddress(payload);
      if (formatted) {
        clientGeocodeCache.set(cacheKey, formatted);
      }
      return formatted;
    } catch (_err) {
      return null;
    }
  }

  function showLocationStatus(msg, isError = false) {
    if (!statusBanner) return;
    statusBanner.classList.remove("hidden", "danger", "warning");
    if (isError) statusBanner.classList.add("danger");
    statusBanner.textContent = msg;
  }

  function updateSharingUI(enabled) {
    sharingEnabled = enabled;
    if (sharingBadge) {
      sharingBadge.className = `badge ${enabled ? "badge-protected" : "badge-lost"}`;
      sharingBadge.textContent = enabled ? "SHARING PERMITTED (ACTIVE)" : "SHARING STOPPED";
    }
    if (!enabled && freshnessBadge && isLiveSessionFix) {
      isLiveSessionFix = false;
      freshnessBadge.className = "badge badge-warning";
      freshnessBadge.textContent = "LAST KNOWN LOCATION (SHARING STOPPED)";
    }
    if (enableBtn) enableBtn.disabled = enabled;
    if (stopBtn) stopBtn.disabled = !enabled;
    if (browserFixBtn) browserFixBtn.disabled = !enabled;
    if (demoFixBtn) demoFixBtn.disabled = !enabled;
    if (testExampleCoordsBtn) testExampleCoordsBtn.disabled = !enabled;
  }

  async function setSharingPermission(enable) {
    try {
      const res = await fetch("/api/location/toggle", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify({
          device_id: deviceId,
          enabled: enable,
          csrf_token: csrfToken
        })
      });
      const data = await res.json();
      if (!data.ok) {
        showLocationStatus(data.error || "Could not update sharing permission.", true);
        return;
      }
      updateSharingUI(data.location_sharing_enabled);
      window.SecurePhoneUI.showToast(data.message, enable ? "success" : "info");
      showLocationStatus(data.message, false);
    } catch (_err) {
      showLocationStatus("Network error while toggling location permission.", true);
    }
  }

  async function recordLocationToServer(lat, lng, accuracy, source) {
    try {
      if (loadingIndicator) loadingIndicator.classList.remove("hidden");
      showLocationStatus("Retrieving exact readable address from OpenStreetMap Nominatim...", false);
      const clientAddress = await reverseGeocodeClient(lat, lng);

      const res = await fetch("/api/location/update", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify({
          device_id: deviceId,
          latitude: lat,
          longitude: lng,
          accuracy: accuracy,
          source: source,
          resolved_address: clientAddress || "",
          csrf_token: csrfToken
        })
      });
      const data = await res.json();
      if (loadingIndicator) loadingIndicator.classList.add("hidden");
      if (!data.ok) {
        showLocationStatus(data.error || "Failed to store location update.", true);
        return;
      }

      isLiveSessionFix = true;
      const readableAddr = data.readable_address || data.location_label || "Address unavailable";
      const localTimeStr = data.recorded_at_local || data.recorded_at;
      const gmapUrl = data.map_links?.google_maps || `https://www.google.com/maps?q=${data.latitude.toFixed(6)},${data.longitude.toFixed(6)}`;
      const osmUrl = data.map_links?.osm || `https://www.openstreetmap.org/?mlat=${data.latitude.toFixed(6)}&mlon=${data.longitude.toFixed(6)}#map=17/${data.latitude.toFixed(6)}/${data.longitude.toFixed(6)}`;

      renderMapMarker(
        data.latitude,
        data.longitude,
        data.accuracy,
        buildPopupHtml(data.latitude, data.longitude, data.accuracy, readableAddr, localTimeStr, true)
      );

      if (freshnessBadge) {
        freshnessBadge.className = "badge badge-protected";
        freshnessBadge.textContent = "LIVE LOCATION (ACTIVE SESSION)";
      }
      if (placeAddressEl) {
        placeAddressEl.textContent = readableAddr;
      }
      if (lastTimeEl) {
        lastTimeEl.textContent = localTimeStr;
      }
      if (lastAccuracyEl) {
        lastAccuracyEl.textContent = `\u00b1${Math.round(data.accuracy)} metres`;
      }
      if (lastCoordsEl) {
        lastCoordsEl.textContent = `${data.latitude.toFixed(6)}, ${data.longitude.toFixed(6)}`;
      }
      if (lastDmsEl && data.dms_coordinates) {
        lastDmsEl.textContent = data.dms_coordinates;
      }
      if (gpsDetailsEl && readableAddr === "Address unavailable") {
        gpsDetailsEl.setAttribute("open", "open");
      }
      if (googleMapsLink) {
        googleMapsLink.href = gmapUrl;
        googleMapsLink.classList.remove("hidden");
      }
      if (osmMapLink) {
        osmMapLink.href = osmUrl;
        osmMapLink.classList.remove("hidden");
      }

      if (data.sos_message && sosPreviewEl) {
        sosPreviewEl.textContent = data.sos_message;
      }
      if (sosModeBadge) {
        sosModeBadge.className = "badge badge-protected";
        sosModeBadge.textContent = "LIVE LOCATION";
      }
      if (sendSosBtn) sendSosBtn.disabled = false;
      if (copySosBtn) copySosBtn.disabled = false;

      if (historyBody) {
        const emptyRow = historyBody.querySelector(".empty-history-row");
        if (emptyRow) emptyRow.remove();
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><code>${escapeHtml(localTimeStr)}</code></td>
          <td><strong>Detected Location:</strong> ${escapeHtml(readableAddr)}</td>
          <td>&plusmn;${Math.round(data.accuracy)} m</td>
          <td>
            <code>${data.latitude.toFixed(6)}, ${data.longitude.toFixed(6)}</code><br>
            <a href="${gmapUrl}" target="_blank" rel="noopener noreferrer" style="font-size:0.78rem;">View on Google Maps &nearr;</a>
            &bull;
            <a href="${osmUrl}" target="_blank" rel="noopener noreferrer" style="font-size:0.78rem;">OSM &nearr;</a>
          </td>
          <td><span class="badge badge-info">${escapeHtml(data.source)}</span></td>
        `;
        historyBody.prepend(tr);
      }

      showLocationStatus(`Detected Location: ${readableAddr} (${localTimeStr}).`, false);
      window.SecurePhoneUI.showToast("Live location & readable address updated.", "success");
    } catch (_err) {
      if (loadingIndicator) loadingIndicator.classList.add("hidden");
      if (gpsDetailsEl) gpsDetailsEl.setAttribute("open", "open");
      showLocationStatus("Failed to communicate with location service.", true);
    }
  }

  if (enableBtn) {
    enableBtn.addEventListener("click", () => setSharingPermission(true));
  }
  if (stopBtn) {
    stopBtn.addEventListener("click", () => setSharingPermission(false));
  }

  if (browserFixBtn) {
    browserFixBtn.addEventListener("click", () => {
      if (!sharingEnabled) {
        showLocationStatus("Please enable Location Sharing permission for this device first.", true);
        return;
      }
      if (!("geolocation" in navigator)) {
        showLocationStatus("Browser Geolocation API is not supported in this browser.", true);
        return;
      }
      showLocationStatus("Requesting browser geolocation permission...", false);
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          recordLocationToServer(
            pos.coords.latitude,
            pos.coords.longitude,
            pos.coords.accuracy || 15.0,
            "browser_geolocation"
          );
        },
        (err) => {
          let reason = "Unable to retrieve browser location.";
          if (err.code === 1) {
            reason = "Browser geolocation permission was denied by the user. You can grant permission in your browser site settings or use the Smart City Demo Check-In button for testing.";
          } else if (err.code === 2) {
            reason = "Location information is currently unavailable from your device hardware.";
          } else if (err.code === 3) {
            reason = "Browser geolocation request timed out.";
          }
          showLocationStatus(reason, true);
          window.SecurePhoneUI.showToast("Geolocation permission denied or unavailable.", "warning");
        },
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
      );
    });
  }

  // Curated Smart City Bengaluru coordinates that resolve cleanly in both Nominatim and offline cache
  const smartCityDemoBeacons = [
    { lat: 12.968271, lng: 77.592483, acc: 11.0 },
    { lat: 12.9716, lng: 77.5946, acc: 12.0 },
    { lat: 12.9784, lng: 77.6408, acc: 18.0 },
    { lat: 12.9352, lng: 77.6245, acc: 14.0 }
  ];
  let demoBeaconIndex = 0;

  if (demoFixBtn) {
    demoFixBtn.addEventListener("click", () => {
      if (!sharingEnabled) {
        showLocationStatus("Please enable Location Sharing permission first.", true);
        return;
      }
      const beacon = smartCityDemoBeacons[demoBeaconIndex % smartCityDemoBeacons.length];
      demoBeaconIndex += 1;
      recordLocationToServer(
        beacon.lat,
        beacon.lng,
        beacon.acc,
        "smartcity_demo_beacon"
      );
    });
  }

  if (testExampleCoordsBtn) {
    testExampleCoordsBtn.addEventListener("click", () => {
      if (!sharingEnabled) {
        showLocationStatus("Please enable Location Sharing permission first.", true);
        return;
      }
      recordLocationToServer(12.968271, 77.592483, 11.0, "nominatim_test_coords");
    });
  }

  if (sendSosBtn) {
    sendSosBtn.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/location/sos", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken
          },
          body: JSON.stringify({
            device_id: deviceId,
            is_live: isLiveSessionFix,
            trusted_contact: sosContactInput ? sosContactInput.value : "",
            csrf_token: csrfToken
          })
        });
        const data = await res.json();
        if (!data.ok) {
          showLocationStatus(data.error || "Could not prepare Trusted Contact SOS alert.", true);
          return;
        }
        if (sosPreviewEl && data.sos_message) {
          sosPreviewEl.textContent = data.sos_message;
        }
        const sosHistoryBody = document.getElementById("sos-history-body");
        if (sosHistoryBody) {
          const emptySos = sosHistoryBody.querySelector(".empty-sos-row");
          if (emptySos) emptySos.remove();
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td><code>#${escapeHtml(data.sos_id || "NEW")}</code></td>
            <td><code>${escapeHtml(data.dispatched_at_local || data.recorded_at_local)}</code></td>
            <td><span class="badge ${data.is_live ? "badge-protected" : "badge-warning"}">${data.is_live ? "LIVE LOCATION" : "LAST RECORDED"}</span></td>
            <td>${escapeHtml(data.trusted_contact || "Owner Self-Dispatch")}</td>
            <td>${escapeHtml(data.readable_address)}</td>
          `;
          sosHistoryBody.prepend(tr);
        }
        window.SecurePhoneUI.showToast("Trusted Contact SOS alert saved to database.", "success");
      } catch (_err) {
        showLocationStatus("Error preparing Trusted Contact SOS alert.", true);
      }
    });
  }

  if (copySosBtn && sosPreviewEl) {
    copySosBtn.addEventListener("click", async () => {
      const text = sosPreviewEl.textContent || "";
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        }
        window.SecurePhoneUI.showToast("SOS alert message copied to clipboard.", "success");
      } catch (_err) {
        window.SecurePhoneUI.showToast("Could not copy automatically; please select and copy the SOS text.", "info");
      }
    });
  }
});

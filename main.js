/**
 * SecurePhone — Global UI & Interaction Controller (Cyber Teal + Violet)
 * Handles:
 * - Theme toggle (Cyber Dark / Cyber Light)
 * - Slim dismissible Smart City Security Notice banner
 * - Collapsible desktop sidebar & responsive mobile slide-out drawer
 * - Profile dropdown menu & Quick Actions dropdown menu (with click-outside & Escape support)
 * - Mobile top navigation toggle
 * - Toast notifications, demo credential helper, and Lost Mode confirmation modal
 */

window.SecurePhoneUI = {
  showToast(message, category = "info") {
    const stack = document.getElementById("toast-stack");
    if (!stack) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${category}`;
    toast.setAttribute("role", "status");

    const span = document.createElement("span");
    span.textContent = message;

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "btn btn-sm btn-secondary";
    closeBtn.textContent = "×";
    closeBtn.setAttribute("aria-label", "Dismiss notification");
    closeBtn.addEventListener("click", () => toast.remove());

    toast.appendChild(span);
    toast.appendChild(closeBtn);
    stack.appendChild(toast);

    setTimeout(() => {
      if (toast.parentElement) toast.remove();
    }, 5500);
  },

  fillDemoCredentials(email, password) {
    const emailInput = document.getElementById("email");
    const pwInput = document.getElementById("password");
    if (emailInput && pwInput) {
      emailInput.value = email;
      pwInput.value = password;
      emailInput.focus();
      this.showToast(`Filled demo credentials for ${email}`, "info");
    }
  },

  setTheme(mode) {
    const root = document.documentElement;
    const validMode = mode === "light" ? "light" : "dark";
    root.setAttribute("data-theme", validMode);
    try {
      localStorage.setItem("securephone_theme", validMode);
    } catch (e) {}
    const labelEl = document.getElementById("theme-toggle-label");
    if (labelEl) {
      labelEl.textContent = validMode === "dark" ? "Cyber Dark" : "Cyber Light";
    }
  },

  toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    this.setTheme(next);
    this.showToast(
      `Switched to Cyber Teal + Violet ${next === "dark" ? "Dark" : "Light"} theme`,
      "info"
    );
  }
};

document.addEventListener("DOMContentLoaded", () => {
  // 1. Initialize Theme Label & Toggle
  const savedTheme = document.documentElement.getAttribute("data-theme") || "dark";
  const labelEl = document.getElementById("theme-toggle-label");
  if (labelEl) {
    labelEl.textContent = savedTheme === "dark" ? "Cyber Dark" : "Cyber Light";
  }

  const themeBtn = document.getElementById("theme-toggle-btn");
  if (themeBtn) {
    themeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      window.SecurePhoneUI.toggleTheme();
    });
  }

  // 2. Dismissible Top Security Notice Banner
  const securityBanner = document.getElementById("top-security-banner");
  const dismissBannerBtn = document.getElementById("dismiss-security-banner-btn");
  if (securityBanner) {
    try {
      if (sessionStorage.getItem("securephone_banner_dismissed") === "1") {
        securityBanner.classList.add("hidden");
      }
    } catch (e) {}
    if (dismissBannerBtn) {
      dismissBannerBtn.addEventListener("click", () => {
        securityBanner.classList.add("hidden");
        try {
          sessionStorage.setItem("securephone_banner_dismissed", "1");
        } catch (e) {}
      });
    }
  }

  // 3. Dropdown Menus (Profile Menu & Quick Actions Menu)
  const dropdownPairs = [
    { btnId: "profile-menu-btn", menuId: "profile-dropdown-menu", wrapId: "profile-dropdown-wrapper" },
    { btnId: "quick-actions-btn", menuId: "quick-actions-menu", wrapId: "quick-actions-wrapper" }
  ];

  function closeAllDropdowns(exceptMenuId = null) {
    dropdownPairs.forEach(({ btnId, menuId }) => {
      if (menuId === exceptMenuId) return;
      const btn = document.getElementById(btnId);
      const menu = document.getElementById(menuId);
      if (menu && !menu.classList.contains("hidden")) {
        menu.classList.add("hidden");
      }
      if (btn) {
        btn.setAttribute("aria-expanded", "false");
      }
    });
  }

  dropdownPairs.forEach(({ btnId, menuId }) => {
    const btn = document.getElementById(btnId);
    const menu = document.getElementById(menuId);
    if (btn && menu) {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const isHidden = menu.classList.contains("hidden");
        closeAllDropdowns(menuId);
        if (isHidden) {
          menu.classList.remove("hidden");
          btn.setAttribute("aria-expanded", "true");
        } else {
          menu.classList.add("hidden");
          btn.setAttribute("aria-expanded", "false");
        }
      });
    }
  });

  document.addEventListener("click", (e) => {
    dropdownPairs.forEach(({ btnId, menuId, wrapId }) => {
      const wrap = document.getElementById(wrapId);
      const menu = document.getElementById(menuId);
      const btn = document.getElementById(btnId);
      if (wrap && menu && !wrap.contains(e.target)) {
        menu.classList.add("hidden");
        if (btn) btn.setAttribute("aria-expanded", "false");
      }
    });
  });

  // 4. Collapsible Desktop Sidebar & Mobile Slide-Out Drawer
  const workspaceGrid = document.getElementById("workspace-grid");
  const sidebar = document.getElementById("workspace-sidebar");
  const sidebarBackdrop = document.getElementById("sidebar-backdrop");
  const sidebarToggleBtn = document.getElementById("sidebar-toggle-btn");
  const sidebarCollapseInnerBtn = document.getElementById("sidebar-collapse-inner-btn");

  function setDesktopCollapsed(collapsed) {
    if (!workspaceGrid) return;
    if (collapsed) {
      workspaceGrid.classList.add("sidebar-collapsed");
    } else {
      workspaceGrid.classList.remove("sidebar-collapsed");
    }
    try {
      localStorage.setItem("securephone_sidebar_collapsed", collapsed ? "1" : "0");
    } catch (e) {}
  }

  function closeMobileDrawer() {
    if (sidebar) sidebar.classList.remove("mobile-drawer-open");
    if (sidebarBackdrop) sidebarBackdrop.classList.add("hidden");
  }

  function toggleSidebar() {
    if (!workspaceGrid || !sidebar) return;
    if (window.innerWidth <= 992) {
      const isOpen = sidebar.classList.toggle("mobile-drawer-open");
      if (sidebarBackdrop) {
        sidebarBackdrop.classList.toggle("hidden", !isOpen);
      }
    } else {
      const nextCollapsed = !workspaceGrid.classList.contains("sidebar-collapsed");
      setDesktopCollapsed(nextCollapsed);
    }
  }

  if (workspaceGrid) {
    try {
      if (window.innerWidth > 992 && localStorage.getItem("securephone_sidebar_collapsed") === "1") {
        workspaceGrid.classList.add("sidebar-collapsed");
      }
    } catch (e) {}
  }

  if (sidebarToggleBtn) {
    sidebarToggleBtn.addEventListener("click", toggleSidebar);
  }
  if (sidebarCollapseInnerBtn) {
    sidebarCollapseInnerBtn.addEventListener("click", toggleSidebar);
  }
  if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener("click", closeMobileDrawer);
  }

  // Close dropdowns & mobile drawer on Escape
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeAllDropdowns();
      closeMobileDrawer();
    }
  });

  // 5. Responsive Top Nav Menu
  const mobileToggle = document.getElementById("mobile-nav-toggle");
  const navLinks = document.getElementById("primary-nav-links");
  if (mobileToggle && navLinks) {
    mobileToggle.addEventListener("click", () => {
      const isOpen = navLinks.classList.toggle("mobile-open");
      mobileToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });
  }

  // 6. Auto-dismiss server-flashed toasts after 6 seconds
  document.querySelectorAll(".toast[data-auto-dismiss]").forEach((el) => {
    setTimeout(() => {
      if (el.parentElement) el.remove();
    }, 6000);
  });

  // 7. Lost Mode confirmation dialog hook
  const lostForm = document.getElementById("lost-mode-form");
  const confirmModal = document.getElementById("lost-confirm-modal");
  const openModalBtn = document.getElementById("trigger-lost-confirm-btn");
  const cancelModalBtn = document.getElementById("cancel-lost-confirm-btn");
  const confirmSubmitBtn = document.getElementById("confirm-lost-submit-btn");

  if (lostForm && confirmModal && openModalBtn) {
    openModalBtn.addEventListener("click", () => {
      if (!lostForm.checkValidity()) {
        lostForm.reportValidity();
        return;
      }
      confirmModal.classList.remove("hidden");
      if (confirmSubmitBtn) confirmSubmitBtn.focus();
    });

    if (cancelModalBtn) {
      cancelModalBtn.addEventListener("click", () => {
        confirmModal.classList.add("hidden");
        openModalBtn.focus();
      });
    }

    if (confirmSubmitBtn) {
      confirmSubmitBtn.addEventListener("click", () => {
        confirmSubmitBtn.disabled = true;
        confirmSubmitBtn.textContent = "Activating Lost Mode...";
        lostForm.submit();
      });
    }
  }
});

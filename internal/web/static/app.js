document.addEventListener("DOMContentLoaded", () => {
    const ownerSelect = document.getElementById("site-owner-select");
    const siteNameInput = document.getElementById("site-name-input");
    const rootPreview = document.getElementById("site-root-preview");

    const computeRootDirectory = () => {
        if (!ownerSelect || !siteNameInput || !rootPreview) {
            return;
        }

        const selectedOption = ownerSelect.options[ownerSelect.selectedIndex];
        const username = selectedOption ? (selectedOption.value || "") : "";
        const siteName = (siteNameInput.value || "").trim();

        if (!username || !siteName) {
            rootPreview.textContent = "Select a Linux user and site name";
            return;
        }

        const rootDirectory = `/var/www/${username}/${siteName}`;

        rootPreview.textContent = rootDirectory;
    };

    ownerSelect?.addEventListener("change", computeRootDirectory);
    siteNameInput?.addEventListener("input", computeRootDirectory);
    computeRootDirectory();

    const deleteSiteModal = document.getElementById("deleteSiteModal");
    if (!deleteSiteModal) {
        return;
    }

    const deleteSiteTitle = document.getElementById("delete-site-title");
    const deleteSiteNameInput = document.getElementById("delete-site-name-input");
    const deleteSiteDomain = document.getElementById("delete-site-domain");
    const deleteSiteMode = document.getElementById("delete-site-mode");
    const deleteSiteUpstream = document.getElementById("delete-site-upstream");
    const deleteSiteRoot = document.getElementById("delete-site-root");
    const deleteSiteConfig = document.getElementById("delete-site-config");
    const deleteSiteForm = document.getElementById("delete-site-form");

    document.querySelectorAll(".delete-site-trigger").forEach((trigger) => {
        trigger.addEventListener("click", () => {
            const siteName = trigger.getAttribute("data-site-name") || "site";
            const siteDomain = trigger.getAttribute("data-site-domain") || "-";
            const siteMode = trigger.getAttribute("data-site-mode") || "-";
            const siteUpstream = trigger.getAttribute("data-site-upstream") || "-";
            const siteRoot = trigger.getAttribute("data-site-root") || "-";
            const siteConfig = trigger.getAttribute("data-site-config") || "-";

            if (deleteSiteTitle) {
                deleteSiteTitle.textContent = `Delete ${siteName}`;
            }
            if (deleteSiteNameInput) {
                deleteSiteNameInput.value = siteName;
            }
            if (deleteSiteDomain) {
                deleteSiteDomain.textContent = siteDomain;
            }
            if (deleteSiteMode) {
                deleteSiteMode.textContent = siteMode;
            }
            if (deleteSiteUpstream) {
                deleteSiteUpstream.textContent = siteUpstream;
            }
            if (deleteSiteRoot) {
                deleteSiteRoot.textContent = siteRoot;
            }
            if (deleteSiteConfig) {
                deleteSiteConfig.textContent = siteConfig;
            }
            if (deleteSiteForm) {
                deleteSiteForm.reset();
                if (deleteSiteNameInput) {
                    deleteSiteNameInput.value = siteName;
                }
            }
        });
    });
});
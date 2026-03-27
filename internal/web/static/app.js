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

    const totpQr = document.getElementById("totp-qr");
    const otpauthUri = totpQr ? (totpQr.getAttribute("data-otpauth-uri") || "") : "";
    if (totpQr && otpauthUri && window.QRCode && typeof window.QRCode.toCanvas === "function") {
        const canvas = document.createElement("canvas");
        totpQr.appendChild(canvas);
        window.QRCode.toCanvas(canvas, otpauthUri, { width: 192, margin: 1 }, () => {});
    }

    const base64UrlToBytes = (value) => {
        const padded = value.replace(/-/g, "+").replace(/_/g, "/");
        const normalized = padded + "=".repeat((4 - (padded.length % 4)) % 4);
        const binary = atob(normalized);
        return Uint8Array.from(binary, (char) => char.charCodeAt(0));
    };

    const bytesToBase64Url = (buffer) => {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        bytes.forEach((value) => {
            binary += String.fromCharCode(value);
        });
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    };

    const preparePublicKeyOptions = (options) => {
        const prepared = JSON.parse(JSON.stringify(options));
        prepared.challenge = base64UrlToBytes(prepared.challenge);
        if (prepared.user && prepared.user.id) {
            prepared.user.id = base64UrlToBytes(prepared.user.id);
        }
        if (Array.isArray(prepared.allowCredentials)) {
            prepared.allowCredentials = prepared.allowCredentials.map((credential) => ({
                ...credential,
                id: base64UrlToBytes(credential.id),
            }));
        }
        if (Array.isArray(prepared.excludeCredentials)) {
            prepared.excludeCredentials = prepared.excludeCredentials.map((credential) => ({
                ...credential,
                id: base64UrlToBytes(credential.id),
            }));
        }
        return prepared;
    };

    const passkeyLoginButton = document.getElementById("passkey-login-button");
    passkeyLoginButton?.addEventListener("click", async () => {
        const usernameInput = document.getElementById("login-username");
        const username = (usernameInput?.value || "").trim();
        if (!username || !window.PublicKeyCredential) {
            return;
        }
        const beginResponse = await fetch("/login/passkey/begin", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            body: new URLSearchParams({ username }),
        });
        const beginPayload = await beginResponse.json();
        if (!beginResponse.ok) {
            window.alert(beginPayload.error || "Passkey login could not be started.");
            return;
        }
        const credential = await navigator.credentials.get({ publicKey: preparePublicKeyOptions(beginPayload.publicKey) });
        if (!credential) {
            return;
        }
        const finishResponse = await fetch("/login/passkey/finish", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                challenge_id: beginPayload.challenge_id,
                credential_id: credential.id,
                client_data_json: bytesToBase64Url(credential.response.clientDataJSON),
                authenticator_data: bytesToBase64Url(credential.response.authenticatorData),
                signature: bytesToBase64Url(credential.response.signature),
            }),
        });
        const finishPayload = await finishResponse.json();
        if (!finishResponse.ok) {
            window.alert(finishPayload.error || "Passkey login failed.");
            return;
        }
        window.location.href = finishPayload.redirect || "/";
    });

    const passkeyRegisterButton = document.getElementById("passkey-register-button");
    passkeyRegisterButton?.addEventListener("click", async () => {
        if (!window.PublicKeyCredential) {
            window.alert("This browser does not support passkeys.");
            return;
        }
        const label = (document.getElementById("passkey-label")?.value || "").trim();
        const beginResponse = await fetch("/settings/passkeys/begin", { method: "POST" });
        const beginPayload = await beginResponse.json();
        if (!beginResponse.ok) {
            window.alert(beginPayload.error || "Passkey registration could not be started.");
            return;
        }
        const credential = await navigator.credentials.create({ publicKey: preparePublicKeyOptions(beginPayload.publicKey) });
        if (!credential) {
            return;
        }
        if (typeof credential.response.getPublicKey !== "function") {
            window.alert("This browser cannot export passkey public keys for server verification.");
            return;
        }
        const publicKey = credential.response.getPublicKey();
        const finishResponse = await fetch("/settings/passkeys/finish", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                challenge_id: beginPayload.challenge_id,
                credential_id: credential.id,
                client_data_json: bytesToBase64Url(credential.response.clientDataJSON),
                public_key_spki: bytesToBase64Url(publicKey),
                label: label,
            }),
        });
        const finishPayload = await finishResponse.json();
        if (!finishResponse.ok) {
            window.alert(finishPayload.error || "Passkey could not be saved.");
            return;
        }
        window.location.reload();
    });
});
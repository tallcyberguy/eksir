# Custom REMnux image — static analysis only.
#
# Extends the upstream remnux/remnux-distro image with YARA-Forge rulesets
# baked in so the static tool wave works out-of-the-box without post-deploy
# bootstrap:
#   1. YARA-Forge core (5,078 rules)     → /usr/local/yara-forge/packages/core/
#   2. YARA-Forge full (11,679 rules)    → /usr/local/yara-forge/packages/full/
#   3. `yara-forge` wrapper script       (uses core)
#   4. `yara-forge-full` wrapper script  (uses full)
#
# **No WINE, no Qiling rootfs, no detonation tooling.** This platform performs
# static analysis only — see backend/isoc_api/adapters/remnux_adapter.py for
# the rationale (TL;DR: container-based dynamic sandboxing is unsafe for any
# sample worth analyzing; ransomware can encrypt the shared workspace volume,
# leftover processes contaminate the next sample's trace, and the kernel
# boundary is too thin. For dynamic analysis, integrate Hybrid Analysis /
# any.run / Triage via their APIs).
#
# To refresh YARA rules: bump YARA_FORGE_RELEASE then:
#   docker compose --profile forensics build remnux
#   docker compose --profile forensics up -d --force-recreate remnux

FROM remnux/remnux-distro:latest

USER root

# YARA-Forge release tag — update this to refresh rules.
# Latest tag listed at https://github.com/YARAHQ/yara-forge/releases/latest
ARG YARA_FORGE_RELEASE=20260524

RUN set -eux; \
    mkdir -p /usr/local/yara-forge/packages/core /usr/local/yara-forge/packages/full; \
    cd /tmp; \
    curl -fsSL "https://github.com/YARAHQ/yara-forge/releases/download/${YARA_FORGE_RELEASE}/yara-forge-rules-core.zip" -o core.zip; \
    curl -fsSL "https://github.com/YARAHQ/yara-forge/releases/download/${YARA_FORGE_RELEASE}/yara-forge-rules-full.zip" -o full.zip; \
    unzip -p core.zip packages/core/yara-rules-core.yar > /usr/local/yara-forge/packages/core/yara-rules-core.yar; \
    unzip -p full.zip packages/full/yara-rules-full.yar > /usr/local/yara-forge/packages/full/yara-rules-full.yar; \
    rm -f core.zip full.zip; \
    printf '#!/bin/bash\nyara -w /usr/local/yara-forge/packages/core/yara-rules-core.yar "${*}"\n' > /usr/local/bin/yara-forge; \
    printf '#!/bin/bash\nyara -w /usr/local/yara-forge/packages/full/yara-rules-full.yar "${*}"\n' > /usr/local/bin/yara-forge-full; \
    chmod +x /usr/local/bin/yara-forge /usr/local/bin/yara-forge-full; \
    echo "core rules: $(grep -c '^rule ' /usr/local/yara-forge/packages/core/yara-rules-core.yar)"; \
    echo "full rules: $(grep -c '^rule ' /usr/local/yara-forge/packages/full/yara-rules-full.yar)"

# Keep the upstream entrypoint behavior — the compose file overrides `command:`.

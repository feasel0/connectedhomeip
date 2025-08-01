ARG VERSION=1
FROM ghcr.io/project-chip/chip-build:${VERSION}
LABEL org.opencontainers.image.source https://github.com/project-chip/connectedhomeip

# ------------------------------------------------------------------------------
# Install dependencies
RUN set -x \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -fy --no-install-recommends \
    7zip \
    cpio \
    libncurses6 \
    openjdk-8-jre-headless \
    wget \
    zip \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists \
    && : # last line

# ------------------------------------------------------------------------------
# Install tizen
ENV TIZEN_VERSION=9.0
ENV TIZEN_SDK_ROOT=/opt/tizen-sdk

COPY tizen-sdk-installer $TIZEN_SDK_ROOT/files/installer
RUN set -x \
    && bash $TIZEN_SDK_ROOT/files/installer/install.sh \
    --verbose \
    --cpu arm,arm64 \
    --tizen-sdk-path $TIZEN_SDK_ROOT \
    --tizen-sdk-data-path /home/ubuntu/tizen-sdk-data \
    --tizen-version $TIZEN_VERSION  \
    --pkg-cache-path /tmp/tizen-pkg/$TIZEN_VERSION \
    --override-secret-tool \
    && rm -rf /tmp/tizen-pkg \
    && : # last line

# ------------------------------------------------------------------------------
# Set environment
# Tools
ENV PATH="$TIZEN_SDK_ROOT/tools/ide/bin:$TIZEN_SDK_ROOT/tools:$PATH"

# ARM
ENV TIZEN_SDK_TOOLCHAIN=$TIZEN_SDK_ROOT/tools/arm-linux-gnueabi-gcc-9.2
ENV TIZEN_SDK_SYSROOT=$TIZEN_SDK_ROOT/platforms/tizen-$TIZEN_VERSION/tizen/rootstraps/tizen-$TIZEN_VERSION-device.core
ENV PATH="$TIZEN_SDK_TOOLCHAIN/bin:$PATH"

# ARM64
ENV TIZEN_SDK_TOOLCHAIN_ARM64=$TIZEN_SDK_ROOT/tools/aarch64-linux-gnu-gcc-9.2
ENV TIZEN_SDK_SYSROOT_ARM64=$TIZEN_SDK_ROOT/platforms/tizen-$TIZEN_VERSION/tizen/rootstraps/tizen-$TIZEN_VERSION-device64.core
ENV PATH="$TIZEN_SDK_TOOLCHAIN_ARM64/bin:$PATH"

# ------------------------------------------------------------------------------
# Switch to the non-root user
USER ubuntu
WORKDIR /home/ubuntu

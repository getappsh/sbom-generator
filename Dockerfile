# ─── Build stage ─────────────────────────────────────────────────────────────
FROM node:19.5.0-alpine AS build

USER root
WORKDIR /node-app

COPY package*.json ./
RUN npm i

COPY . .
RUN npm run build

# ─── Production stage ─────────────────────────────────────────────────────────
FROM node:19.5.0-alpine AS deploy

USER root
WORKDIR /node-app

ENV NODE_ENV=production

# Install Syft CLI as a step in the image build so we are NOT coupled to a
# Syft base image. The curl+sh installer is the official distribution method.
# pinning with SYFT_INSTALL_VERSION ensures reproducible builds.
ARG SYFT_INSTALL_VERSION=v1.18.1
ARG GRYPE_INSTALL_VERSION=v0.87.0
RUN apk --no-cache add curl bash && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin "${SYFT_INSTALL_VERSION}" && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b /usr/local/bin "${GRYPE_INSTALL_VERSION}" && \
    apk del curl bash && \
    syft version && grype version

COPY package*.json ./
RUN npm install --only=production --omit=dev

COPY --from=build /node-app/dist/ .

ARG sbom_generator_version_tag
ENV sbom_generator_version_tag=$sbom_generator_version_tag
RUN echo "$sbom_generator_version_tag" > sbom_generator_image_version.txt

CMD ["node", "apps/sbom-generator/main.js"]


# syntax=docker/dockerfile:1
#
# Copyright (C) 2022, Berachain Foundation. All rights reserved.
# See the file LICENSE for licensing terms.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#######################################################
###           Stage 0 - Build Arguments             ###
#######################################################

ARG GO_VERSION=1.22.2
ARG RUNNER_IMAGE=alpine:3.19
ARG BUILD_TAGS="netgo,ledger,muslc,blst,pebbledb"
ARG NAME=beacond
ARG APP_NAME=beacond
ARG DB_BACKEND=pebbledb
ARG CMD_PATH=./beacond/cmd


#######################################################
###         Stage 1 - Build the Application         ###
#######################################################

FROM golang:${GO_VERSION}-alpine3.19 as builder

ARG GIT_VERSION
ARG GIT_COMMIT
ARG BUILD_TAGS

# Consolidate RUN commands to reduce layers
RUN apk add --no-cache ca-certificates build-base linux-headers git && \
    set -eux

# Set the working directory
WORKDIR /workdir

# Copy the go.mod and go.sum files for each module
COPY ./beacond/go.mod ./beacond/go.sum ./beacond/
COPY ./mod/beacon/go.mod ./mod/beacon/go.sum ./mod/beacon/
COPY ./mod/core/go.mod ./mod/core/go.sum ./mod/core/
COPY ./mod/da/go.mod ./mod/da/go.sum ./mod/da/
COPY ./mod/execution/go.mod ./mod/execution/go.sum ./mod/execution/
COPY ./mod/log/go.mod ./mod/log/
COPY ./mod/node-builder/go.mod ./mod/core/go.sum ./mod/node-builder/
COPY ./mod/payload/go.mod ./mod/payload/go.sum ./mod/payload/
COPY ./mod/primitives/go.mod ./mod/primitives/go.sum ./mod/primitives/
COPY ./mod/primitives-engine/go.mod ./mod/primitives-engine/go.sum ./mod/primitives-engine/
COPY ./mod/runtime/go.mod ./mod/runtime/go.sum ./mod/runtime/
COPY ./mod/storage/go.mod ./mod/storage/go.sum ./mod/storage/
RUN go work init
RUN go work use ./beacond
RUN go work use ./mod/beacon
RUN go work use ./mod/core
RUN go work use ./mod/da
RUN go work use ./mod/execution
RUN go work use ./mod/log
RUN go work use ./mod/node-builder
RUN go work use ./mod/payload
RUN go work use ./mod/primitives
RUN go work use ./mod/primitives-engine
RUN go work use ./mod/runtime
RUN go work use ./mod/storage


# Download the go module dependencies
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    go mod download

# Copy the rest of the source code
COPY ./mod ./mod
COPY ./beacond ./beacond

# Build args
ARG NAME
ARG APP_NAME
ARG DB_BACKEND
ARG CMD_PATH

# Build beacond
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    env NAME=${NAME} DB_BACKEND=${DB_BACKEND} APP_NAME=${APP_NAME} CGO_ENABLED=1 && \
    go build \
    -mod=readonly \
    -tags ${BUILD_TAGS} \
    -ldflags "-X github.com/cosmos/cosmos-sdk/version.Name=${NAME} \
    -X github.com/cosmos/cosmos-sdk/version.AppName=${APP_NAME} \
    -X github.com/cosmos/cosmos-sdk/version.Version=${GIT_VERSION} \
    -X github.com/cosmos/cosmos-sdk/version.Commit=${GIT_COMMIT} \
    -X github.com/cosmos/cosmos-sdk/version.BuildTags=${BUILD_TAGS} \
    -X github.com/cosmos/cosmos-sdk/types.DBBackend=$DB_BACKEND \
    -w -s -linkmode=external -extldflags '-Wl,-z,muldefs -static'" \
    -trimpath \
    -o /workdir/build/bin/beacond \
    ${CMD_PATH}

#######################################################
###        Stage 2 - Prepare the Final Image        ###
#######################################################

FROM ${RUNNER_IMAGE}

# Build args
ARG APP_NAME

COPY --from=ghcr.io/foundry-rs/foundry /usr/local/bin/forge /usr/bin/forge 
COPY --from=ghcr.io/foundry-rs/foundry /usr/local/bin/cast /usr/bin/cast
COPY --from=ghcr.io/foundry-rs/foundry /usr/local/bin/anvil /usr/bin/anvil
COPY --from=ghcr.io/foundry-rs/foundry /usr/local/bin/chisel /usr/bin/chisel

# Copy over built executable into a fresh container.
COPY --from=builder /workdir/build/bin/${APP_NAME} /usr/bin
RUN mkdir -p /root/jwt /root/kzg && \
    apk add --no-cache bash sed curl jq

#ENTRYPOINT [ "./beacond" ]

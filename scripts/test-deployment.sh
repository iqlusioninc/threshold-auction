#!/bin/bash
# Test deployment script for threshold auction system
#
# This script sets up a local test environment with:
# - Mock chain server
# - 3 validators with shared keys
# - Example auction flow

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_DIR/test-data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Build all binaries
build() {
    info "Building all binaries..."
    cargo build --release -p auction-mock-chain -p auction-validator -p auction-client
    info "Build complete"
}

# Clean up data directory
clean() {
    info "Cleaning up test data..."
    rm -rf "$DATA_DIR"
    mkdir -p "$DATA_DIR"
}

# Generate validator keys
generate_keys() {
    info "Generating validator keys..."
    mkdir -p "$DATA_DIR/validators"

    for i in 1 2 3; do
        info "  Generating keys for validator $i..."
        "$PROJECT_DIR/target/release/validator" \
            --index $i \
            --total 3 \
            --threshold 2 \
            --data-dir "$DATA_DIR/validators" \
            keygen
    done

    info "Validator keys generated"
}

# Start mock chain
start_mock_chain() {
    info "Starting mock chain server..."
    "$PROJECT_DIR/target/release/mock-chain" &
    MOCK_CHAIN_PID=$!
    echo $MOCK_CHAIN_PID > "$DATA_DIR/mock-chain.pid"
    sleep 2
    info "Mock chain started (PID: $MOCK_CHAIN_PID)"
}

# Stop mock chain
stop_mock_chain() {
    if [ -f "$DATA_DIR/mock-chain.pid" ]; then
        PID=$(cat "$DATA_DIR/mock-chain.pid")
        if kill -0 $PID 2>/dev/null; then
            info "Stopping mock chain (PID: $PID)..."
            kill $PID
            rm "$DATA_DIR/mock-chain.pid"
        fi
    fi
}

# Setup chain with master key
setup_chain() {
    info "Setting up chain with master public key..."
    "$PROJECT_DIR/target/release/validator" \
        --index 1 \
        --data-dir "$DATA_DIR/validators" \
        --rpc "http://127.0.0.1:9944" \
        setup-chain
    info "Chain setup complete"
}

# Run a demo auction flow
demo_auction() {
    info "Running demo auction flow..."

    CLI="$PROJECT_DIR/target/release/auction-cli"

    # Get current timestamp and set chain time
    CURRENT_TIME=$(date +%s)
    START_TIME=$((CURRENT_TIME + 10))
    END_TIME=$((CURRENT_TIME + 300))
    DECRYPT_ROUND=$((CURRENT_TIME + 350))
    SETTLE_DEADLINE=$((CURRENT_TIME + 600))

    info "Setting chain timestamp to $CURRENT_TIME..."
    $CLI set-timestamp --timestamp $CURRENT_TIME

    info "Creating auction..."
    $CLI create-auction \
        --sender "0101010101010101010101010101010101010101010101010101010101010101" \
        --auction-type "second_price" \
        --start-time $START_TIME \
        --end-time $END_TIME \
        --decryption-round $DECRYPT_ROUND \
        --settlement-deadline $SETTLE_DEADLINE \
        --min-bid 10 \
        --reserve-price 50

    info "Advancing time to bidding period..."
    $CLI set-timestamp --timestamp $((START_TIME + 10))

    info "Submitting bid from Alice (100)..."
    $CLI bid \
        --sender "a]ic3000000000000000000000000000000000000000000000000000000000001" \
        --auction-id 1 \
        --amount 100 \
        --deposit 100

    info "Submitting bid from Bob (200)..."
    $CLI bid \
        --sender "b0b0000000000000000000000000000000000000000000000000000000000002" \
        --auction-id 1 \
        --amount 200 \
        --deposit 200

    info "Submitting bid from Carol (150)..."
    $CLI bid \
        --sender "ca401000000000000000000000000000000000000000000000000000000003" \
        --auction-id 1 \
        --amount 150 \
        --deposit 150

    info "Listing bids..."
    $CLI get-bids --auction-id 1

    info "Getting auction status..."
    $CLI get-auction --auction-id 1

    info "Demo auction created with 3 bids"
    info ""
    info "To complete the auction flow manually:"
    info "  1. Advance time past end: $CLI set-timestamp --timestamp $((END_TIME + 10))"
    info "  2. Submit partial decryptions from validators"
    info "  3. Aggregate decryption key: $CLI aggregate-decryption --auction-id 1 --round $DECRYPT_ROUND --validators '1,2'"
    info "  4. Settle auction: $CLI settle --sender <settler> --auction-id 1 --winner <winner> --winning-price <price> --winner-index <idx> --num-valid-bids 3"
}

# Main commands
case "${1:-}" in
    build)
        build
        ;;
    clean)
        clean
        ;;
    keygen)
        generate_keys
        ;;
    start)
        start_mock_chain
        ;;
    stop)
        stop_mock_chain
        ;;
    setup)
        setup_chain
        ;;
    demo)
        demo_auction
        ;;
    all)
        clean
        build
        generate_keys
        start_mock_chain
        sleep 1
        setup_chain
        demo_auction
        ;;
    *)
        echo "Threshold Auction Test Deployment"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  build   - Build all binaries"
        echo "  clean   - Clean test data directory"
        echo "  keygen  - Generate validator keys"
        echo "  start   - Start mock chain server"
        echo "  stop    - Stop mock chain server"
        echo "  setup   - Setup chain with master public key"
        echo "  demo    - Run demo auction flow"
        echo "  all     - Run full setup (clean, build, keygen, start, setup, demo)"
        echo ""
        echo "Example full flow:"
        echo "  $0 all"
        echo ""
        echo "Example manual flow:"
        echo "  $0 build"
        echo "  $0 clean"
        echo "  $0 keygen"
        echo "  $0 start"
        echo "  $0 setup"
        echo "  $0 demo"
        echo "  # ... interact with auction-cli ..."
        echo "  $0 stop"
        ;;
esac

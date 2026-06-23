/**
 * IoMT CardioAI — Frontend Configuration
 * Edit API_BASE_URL to point at your deployed backend.
 */
window.CARDIOAI_CONFIG = {
  // REST API for dashboard live data (served by aiohttp on port 8080)
  API_BASE_URL: "https://cardioai.hospital.local/api",

  // WebSocket endpoint (iOS app + IoMT devices)
  WS_URL: "wss://cardioai.hospital.local/stream",

  // How often the dashboard polls the backend (ms)
  POLL_INTERVAL_MS: 5000,

  // Environment label shown in the UI
  ENV_LABEL: "Production",
};

import { handleScanRequest } from "./_shared.js";

export default {
  async fetch(request) {
    return handleScanRequest(request);
  }
};

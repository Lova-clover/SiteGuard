import { handleAdminMetricsRequest } from "../_shared.js";

export default {
  async fetch(request) {
    return handleAdminMetricsRequest(request);
  }
};

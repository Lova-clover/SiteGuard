import { handleAdminSessionRequest } from "../_shared.js";

export default {
  async fetch(request) {
    return handleAdminSessionRequest(request);
  }
};

import { handleAdminLogoutRequest } from "../_shared.js";

export default {
  async fetch(request) {
    return handleAdminLogoutRequest(request);
  }
};

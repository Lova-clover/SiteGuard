import { handleAdminLoginRequest } from "../_shared.js";

export default {
  async fetch(request) {
    return handleAdminLoginRequest(request);
  }
};

import { handleHealthRequest } from "./_shared.js";

export default {
  async fetch(request) {
    return handleHealthRequest(request);
  }
};

import { handleVisitRequest } from "../_shared.js";

export default {
  async fetch(request) {
    return handleVisitRequest(request);
  }
};

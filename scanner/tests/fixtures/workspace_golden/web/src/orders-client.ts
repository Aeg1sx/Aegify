import axios from "axios";

export async function loadOrder(id: string) {
  return axios.get(`/edge/v1/orders/${id}`);
}

export async function cancelOrder(id: string, reason: string) {
  return axios.post(`/edge/v1/orders/${id}/cancel`, { reason });
}

import axios from "axios";

// Backend adresi
const BASE_URL = "http://localhost:5000";

const api = axios.create({
  baseURL: BASE_URL,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
}, (error) => Promise.reject(error));

api.interceptors.response.use(
  (response) => {
    // Backend veriyi { Data: ... } içinde gönderiyorsa onu çıkar
    if (response.data && response.data.Data !== undefined) return response.data.Data;
    if (response.data && response.data.data !== undefined) return response.data.data;
    return response.data;
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("token");
      window.location.href = "/";
    }
    return Promise.reject(error);
  }
);

// --- SERVİSLER ---

export const authService = {
  login: (username, password) => api.post("/api/auth/login", { username, password }),
  register: (data) => api.post("/api/auth/register", data),
  getUsers: () => api.get("/api/auth/users"),
  deleteUser: (id) => api.delete(`/api/auth/users/${id}`),
};

export const deletionRequestService = {
  getPending: () => api.get("/api/deletion-requests/pending"),
  approve: (id) => api.post(`/api/deletion-requests/approve/${id}`),
  reject: (id) => api.post(`/api/deletion-requests/reject/${id}`),
};

export const orderService = {
  getAll: () => api.get("/api/siparis"),
  create: (data) => api.post("/api/siparis", data),
  search: (text) => api.get(`/api/siparis/ara/${text}`),
  update: (data) => api.put("/api/siparis/guncelle", data),
  // SİLME FONKSİYONU BURADA:
  delete: (id, note = "") => api.delete(`/api/siparis/${id}?note=${encodeURIComponent(note)}`),
};

export const personnelService = {
  getAll: () => api.get("/api/personel"),
  create: (data) => api.post("/api/personel", data),
  update: (data) => api.put("/api/personel", data),
  // SİLME FONKSİYONU BURADA:
  delete: (id) => api.delete(`/api/personel/${id}`),
};

export const expenseService = {
  getAll: () => api.get("/api/ek-muhasebe"),
  create: (data) => api.post("/api/ek-muhasebe", data),
  // SİLME FONKSİYONU BURADA:
  delete: (id) => api.delete(`/api/ek-muhasebe/${id}`),
};

export const dashboardService = {
  getStats: () => api.get("/api/dashboard/ozet"),
};
// src/api.js dosyasının mevcut kodlarının altına ekleyin:

export const catalogService = {
  // GET
  getAllCategories: () => api.get("/api/Catalog/categories"),
  getAllProducts: () => api.get("/api/Catalog/products"),

  // CREATE (POST)
  createCategory: (data) => api.post("/api/Catalog/categories", data),
  
  // Ürün oluştururken (HasMicron bilgisi burada gider)
  createProduct: (data) => api.post("/api/Catalog/products", data),

  // Varyant oluştururken (Body içinde { productId: 1, hasSubParts: true ... } gider)
  createVariant: (data) => api.post("/api/Catalog/variants", data),

  // Parça oluştururken (Body içinde { variantId: 1, price: 3000 ... } gider)
  createPartPrice: (data) => api.post("/api/Catalog/parts", data),

  // UPDATE (PUT)
  updateCategory: (data) => api.put("/api/Catalog/categories", data),
  updateProduct: (data) => api.put("/api/Catalog/products", data),
  updateVariant: (data) => api.put("/api/Catalog/variants", data),
  updatePartPrice: (data) => api.put("/api/Catalog/parts", data),

  // DELETE
  deleteCategory: (id) => api.delete(`/api/Catalog/categories/${id}`),
  deleteProduct: (id) => api.delete(`/api/Catalog/products/${id}`),
  deleteVariant: (id) => api.delete(`/api/Catalog/variants/${id}`),
  deletePartPrice: (id) => api.delete(`/api/Catalog/parts/${id}`),
};
export default api;
import React, { useState } from "react";
import { Car, Loader2, AlertCircle } from "lucide-react";
import { authService } from "../api";
import bgImage from "../assets/bg.jpg";

const LoginView = ({ onLogin }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await authService.login(username, password);
      console.log("Login Yanıtı:", response);

      // Yanıt boşsa veya null ise
      if (!response) throw new Error("Sunucudan yanıt alınamadı!");

      // Token'ı farklı formatlarda arayalım (Büyük/Küçük harf)
      const token = response.Token || response.token || response.data?.token;
      
      if (token) {
        const userData = {
          name: response.FullName || response.fullName || username,
          role: response.Role || response.role || "Admin",
          token: token
        };
        onLogin(userData);
      } else {
        throw new Error("Kullanıcı adı veya şifre hatalı!");
      }

    } catch (err) {
      console.error(err);
      setError(err.message || "Giriş yapılamadı.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div 
      className="min-h-screen flex items-center justify-center p-4 transition-colors duration-300
      bg-gray-100 dark:bg-dark-bg"
    >
      <div className="rounded-2xl shadow-xl w-full max-w-md p-8 border transition-all duration-300
        bg-white border-gray-200
        dark:bg-dark-card dark:border-dark-border">
        <div className="text-center mb-8">
          <img src={bgImage} alt="Logo" className="w-24 h-24 mx-auto mb-4 object-contain rounded-full shadow-lg" />
          <h1 className="text-3xl font-bold mb-2 text-gray-800 dark:text-gray-100">Bağlan Oto</h1>
          <p className="text-gray-500 dark:text-gray-400">Yönetim Paneli Girişi</p>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg flex items-center gap-2 text-sm
            bg-red-50 border border-red-200 text-red-600
            dark:bg-red-900/30 dark:border-red-800 dark:text-red-400">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

                <form onSubmit={handleLogin} className="space-y-5">
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-400">Kullanıcı Adı</label>
            <input type="text" name="username" id="username" value={username} onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-3 border rounded-lg outline-none transition-colors
                bg-white border-gray-300 text-gray-900 focus:ring-2 focus:ring-blue-500 placeholder-gray-400
                dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500"
              placeholder="admin" required autoComplete="username" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-400">Şifre</label>
            <input type="password" name="password" id="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 border rounded-lg outline-none transition-colors
                bg-white border-gray-300 text-gray-900 focus:ring-2 focus:ring-blue-500 placeholder-gray-400
                dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500"
              placeholder="••••••••" required autoComplete="current-password" />
          </div>
          <button type="submit" disabled={loading}
            className="w-full py-3 rounded-lg font-bold flex items-center justify-center gap-2 disabled:opacity-70 shadow-lg transition-all
              bg-blue-600 text-white hover:bg-blue-700 shadow-blue-200
              dark:bg-brand dark:text-white dark:hover:bg-brand-dark dark:shadow-brand/20">
            {loading ? <><Loader2 className="animate-spin" size={20} /> Giriş...</> : "Giriş Yap"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default LoginView;
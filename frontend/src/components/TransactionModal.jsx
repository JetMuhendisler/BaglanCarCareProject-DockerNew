import React, { useState } from "react";
import { X, ArrowDown, ArrowUp } from "lucide-react";

const AddTransactionModal = ({ onClose, onAdd }) => {
  const [data, setData] = useState({
    type: "income", // "income" veya "expense"
    category: "",   
    description: "",
    amount: "",
    date: new Date().toISOString().split("T")[0],
  });

  const categories = {
    income: ["Hizmet", "Ek Gelir", "Bahşiş", "Diğer"],
    expense: ["Malzeme", "Kira", "Fatura", "Yemek", "Maaş", "Diğer"],
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="rounded-lg max-w-md w-full p-6 shadow-xl transition-colors
        bg-white dark:bg-dark-card dark:border dark:border-dark-border">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-800 dark:text-gray-100">Yeni İşlem Ekle</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"><X size={24} /></button>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <button onClick={() => setData({ ...data, type: "income" })} className={`p-3 rounded-lg border-2 flex justify-center items-center gap-2 transition-colors font-medium
              ${data.type === "income" 
                ? "border-green-500 bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-400 dark:border-green-600" 
                : "border-gray-200 text-gray-600 dark:border-dark-border dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-dark-hover"}`}>
              <ArrowDown size={20} /> Gelir
            </button>
            <button onClick={() => setData({ ...data, type: "expense" })} className={`p-3 rounded-lg border-2 flex justify-center items-center gap-2 transition-colors font-medium
              ${data.type === "expense" 
                ? "border-red-500 bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400 dark:border-red-600" 
                : "border-gray-200 text-gray-600 dark:border-dark-border dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-dark-hover"}`}>
              <ArrowUp size={20} /> Gider
            </button>
          </div>

          <select className="w-full border rounded-lg px-4 py-2 outline-none focus:ring-2 transition-colors
            border-gray-300 bg-white text-gray-900 focus:ring-blue-500
            dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" value={data.category} onChange={(e) => setData({ ...data, category: e.target.value })}>
            <option value="">Kategori Seçiniz</option>
            {categories[data.type].map((cat) => <option key={cat} value={cat}>{cat}</option>)}
          </select>

          <input type="text" placeholder="Açıklama" className="w-full border rounded-lg px-4 py-2 outline-none focus:ring-2 transition-colors
            border-gray-300 bg-white text-gray-900 focus:ring-blue-500
            dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" value={data.description} onChange={(e) => setData({ ...data, description: e.target.value })} />
          <input type="number" placeholder="Tutar (TL)" className="w-full border rounded-lg px-4 py-2 outline-none focus:ring-2 transition-colors
            border-gray-300 bg-white text-gray-900 focus:ring-blue-500
            dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" value={data.amount} onChange={(e) => setData({ ...data, amount: e.target.value })} />
          <input type="date" className="w-full border rounded-lg px-4 py-2 outline-none focus:ring-2 transition-colors
            border-gray-300 bg-white text-gray-900 focus:ring-blue-500
            dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" value={data.date} onChange={(e) => setData({ ...data, date: e.target.value })} />
        </div>

        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 px-4 py-2 border rounded-lg transition-colors
            border-gray-300 text-gray-700 hover:bg-gray-50
            dark:border-dark-border dark:text-gray-300 dark:hover:bg-dark-hover">İptal</button>
          <button onClick={() => onAdd(data)} disabled={!data.amount || !data.category} className="flex-1 px-4 py-2 rounded-lg text-white font-bold transition-colors disabled:opacity-50
            bg-blue-600 hover:bg-blue-700
            dark:bg-brand dark:hover:bg-brand-dark dark:text-white">Kaydet</button>
        </div>
      </div>
    </div>
  );
};

export default AddTransactionModal;
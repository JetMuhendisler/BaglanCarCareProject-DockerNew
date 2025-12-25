import React, { useState, useEffect } from "react";
import { X, Save, User, FileText, Activity, Check, DollarSign } from "lucide-react"; // DollarSign ikonunu ekledik
import { orderService } from "../api";

const OrderDetailModal = ({ order, staff, onClose, onSave }) => {
  // Statü ID çevirici (Mevcut kodun)
  const getStatusId = (statusStr) => {
    if (!statusStr) return 1;
    const s = statusStr.toLowerCase();
    if (s.includes("bekliyor") || s.includes("pending")) return 1;
    if (s.includes("işlemde") || s.includes("progress")) return 2;
    if (s.includes("tamam") || s.includes("completed")) return 3;
    if (s.includes("iptal") || s.includes("cancel")) return 4;
    return 1;
  };

  const [personnelIds, setPersonnelIds] = useState(order.personnelIds || []);
  const [statusId, setStatusId] = useState(1);
  const [description, setDescription] = useState(order.description || "");
  
  // --- YENİ STATE: Ödeme Durumu ---
  const [isPaid, setIsPaid] = useState(order.isPaid || false); 
  // -------------------------------
  
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setStatusId(getStatusId(order.status));
  }, [order.status]);

  const toggleStaff = (id) => {
    setPersonnelIds((prev) =>
      prev.includes(id) ? prev.filter((pid) => pid !== id) : [...prev, id]
    );
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      const payload = {
        orderId: order.id,
        statusId: parseInt(statusId),
        description: description,
        personnelIds: personnelIds,
        // --- YENİ ALANI GÖNDERİYORUZ ---
        isPaid: isPaid 
      };

      await orderService.update(payload);
      onSave(); 
    } catch (error) {
      alert("Hata: " + (error.response?.data?.Message || error.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] transition-colors
        bg-white dark:bg-dark-card">
        
        {/* BAŞLIK */}
        <div className="p-4 border-b flex justify-between items-center transition-colors
          bg-gray-50 border-gray-200
          dark:bg-dark-card dark:border-dark-border">
          <div>
            <h3 className="font-bold text-lg text-gray-800 dark:text-gray-100">İş Emri Düzenle</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400">#{order.id} - {order.plate}</p>
          </div>
          <button onClick={onClose} className="p-2 rounded-full transition-colors text-gray-500 hover:text-red-500 hover:bg-gray-200 dark:text-gray-400 dark:hover:bg-dark-hover dark:hover:text-red-400"><X size={20}/></button>
        </div>

        {/* İÇERİK */}
        {/* İÇERİK */}
        <div className="p-6 space-y-6 overflow-y-auto">
          
          {/* DURUM BUTONLARI */}
          <div>
            <label className="text-sm font-bold mb-2 flex items-center gap-2 text-gray-700 dark:text-gray-300">
              <Activity size={16} className="text-blue-600 dark:text-brand"/> İşlem Durumu
            </label>
            <div className="grid grid-cols-4 gap-2">
              {[
                { id: 1, label: "Bekliyor", color: "bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-500 dark:border-yellow-800" },
                { id: 2, label: "İşlemde", color: "bg-blue-50 text-blue-700 border-blue-200 dark:bg-brand/10 dark:text-brand dark:border-brand/30" },
                { id: 3, label: "Tamamlandı", color: "bg-green-50 text-green-700 border-green-200 dark:bg-green-900/30 dark:text-green-500 dark:border-green-800" },
                { id: 4, label: "İptal", color: "bg-red-50 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-500 dark:border-red-800" }
              ].map((s) => (
                <button
                  key={s.id}
                  onClick={() => setStatusId(s.id)}
                  className={`py-2 text-xs font-bold rounded-lg border transition-all relative
                    ${statusId === s.id 
                      ? `${s.color} ring-2 ring-offset-1 ring-gray-300 dark:ring-dark-border scale-105 shadow-md border-transparent` 
                      : "bg-white border-gray-200 text-gray-500 hover:bg-gray-50 dark:bg-dark-bg dark:border-dark-border dark:text-gray-400 dark:hover:bg-dark-hover"
                    }`}
                >
                  {s.label}
                  {statusId === s.id && <Check size={12} className="absolute top-1 right-1"/>}
                </button>
              ))}
            </div>
          </div>

          {/* --- YENİ EKLENEN ÖDEME BÖLÜMÜ --- */}
          <div className="p-3 rounded-lg border flex justify-between items-center transition-colors
            bg-gray-50 border-gray-200
            dark:bg-dark-bg/50 dark:border-dark-border">
            <div className="flex items-center gap-2">
                <div className="p-2 rounded-full text-green-600 dark:text-brand bg-green-100 dark:bg-brand/10">
                    <DollarSign size={20} />
                </div>
                <div>
                    <p className="text-sm font-bold text-gray-800 dark:text-gray-200">Ödeme Durumu</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{isPaid ? "Tahsilat yapıldı." : "Ödeme bekleniyor."}</p>
                </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
                <input 
                    type="checkbox" 
                    className="sr-only peer" 
                    checked={isPaid} 
                    onChange={(e) => setIsPaid(e.target.checked)} 
                />
                <div className="w-11 h-6 bg-gray-200 dark:bg-dark-hover peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600 dark:peer-checked:bg-brand"></div>
                <span className="ml-3 text-sm font-medium text-gray-700 dark:text-gray-300">{isPaid ? "Ödendi" : "Ödenmedi"}</span>
            </label>
          </div>
          {/* ----------------------------------- */}

          {/* PERSONEL LİSTESİ */}
          <div>
            <label className="text-sm font-bold mb-2 flex items-center gap-2 text-gray-700 dark:text-gray-300">
              <User size={16} className="text-purple-600 dark:text-purple-400"/> Personel Seçimi
            </label>
            <div className="border rounded-lg p-2 max-h-48 overflow-y-auto space-y-2
              bg-gray-50/50 border-gray-200
              dark:bg-dark-bg/50 dark:border-dark-border">
              {staff.map((p) => {
                const isSelected = personnelIds.includes(p.id);
                return (
                  <div key={p.id} onClick={() => toggleStaff(p.id)}
                    className={`flex items-center gap-3 p-2 rounded-md cursor-pointer transition-all border
                      ${isSelected 
                        ? "bg-purple-100 border-purple-300 shadow-sm dark:bg-purple-900/30 dark:border-purple-800" 
                        : "bg-white border-gray-200 hover:border-blue-300 dark:bg-dark-card dark:border-dark-border dark:hover:border-brand/50"}`}>
                    <div className={`w-5 h-5 rounded border flex items-center justify-center transition-colors 
                      ${isSelected ? "bg-purple-600 border-purple-600 dark:bg-purple-700 dark:border-purple-700" : "bg-white border-gray-400 dark:bg-dark-bg dark:border-gray-600"}`}>
                      {isSelected && <Check size={14} className="text-white" />}
                    </div>
                    <span className={`text-sm font-medium ${isSelected ? "text-purple-900 dark:text-purple-300" : "text-gray-700 dark:text-gray-300"}`}>
                      {p.name || "İsimsiz Personel"} 
                    </span>
                  </div>
                );
              })}
              {staff.length === 0 && <div className="text-gray-400 text-xs text-center py-2">Personel bulunamadı.</div>}
            </div>
          </div>

          {/* NOTLAR */}
          <div>
            <label className="text-sm font-bold mb-2 flex items-center gap-2 text-gray-700 dark:text-gray-300">
              <FileText size={16} className="text-gray-600 dark:text-gray-400"/> Not / Açıklama
            </label>
            <textarea className="w-full border p-3 rounded-lg text-sm focus:ring-2 outline-none min-h-[80px] transition-colors
              border-gray-300 text-gray-900 focus:ring-blue-500
              dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand dark:placeholder-gray-500"
              placeholder="Not giriniz..." value={description} onChange={(e) => setDescription(e.target.value)}/>
          </div>
        </div>

        {/* KAYDET BUTONU */}
        <div className="p-4 border-t flex justify-end gap-3 transition-colors
          bg-gray-50 border-gray-200
          dark:bg-dark-card dark:border-dark-border">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm font-medium transition-colors
            text-gray-600 hover:bg-gray-200 
            dark:text-gray-400 dark:hover:bg-dark-hover">İptal</button>
          <button onClick={handleSave} disabled={loading}
            className="px-6 py-2 rounded-lg text-sm font-bold flex items-center gap-2 shadow-lg disabled:opacity-70 transition-all
             bg-blue-600 text-white hover:bg-blue-700 shadow-blue-200
             dark:bg-brand dark:text-white dark:hover:bg-brand-dark dark:shadow-brand/20">
            {loading ? "Kaydediliyor..." : <><Save size={16}/> Kaydet</>}
          </button>
        </div>
      </div>
    </div>
  );
};

export default OrderDetailModal;
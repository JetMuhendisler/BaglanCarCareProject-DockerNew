import React, { useState } from "react";
import { X, Save, User, DollarSign, Calendar, Briefcase } from "lucide-react";
// personnelService importuna gerek yok, sildik.

// --- YENİ PERSONEL EKLEME MODALI ---
export const AddStaffModal = ({ onClose, onAdd }) => {
  const [formData, setFormData] = useState({
    firstName: "", 
    lastName: "",  
    role: "",
    salary: "",
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    // Veriyi Dashboard'a gönder (API çağrısı orada yapılacak)
    onAdd(formData);
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4 backdrop-blur-sm animate-in fade-in">
      <div className="w-full max-w-md rounded-2xl shadow-2xl p-6 relative transition-colors
        bg-white dark:bg-dark-card dark:border dark:border-dark-border">
        <button onClick={onClose} className="absolute top-4 right-4 transition-colors
          text-gray-400 hover:text-red-500
          dark:text-gray-500 dark:hover:text-red-400">
          <X size={20} />
        </button>
        
        <h3 className="text-xl font-bold mb-6 flex items-center gap-2 text-gray-800 dark:text-gray-100">
          <User className="text-blue-600 dark:text-brand"/> Yeni Personel Ekle
        </h3>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Ad</label>
              <input 
                className="w-full border p-3 rounded-lg outline-none focus:ring-2 transition-colors
                  border-gray-300 text-gray-900 focus:ring-blue-500
                  dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" 
                placeholder="Örn: Mahmut" 
                value={formData.firstName} 
                onChange={e => setFormData({...formData, firstName: e.target.value})} 
                required 
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Soyad</label>
              <input 
                className="w-full border p-3 rounded-lg outline-none focus:ring-2 transition-colors
                  border-gray-300 text-gray-900 focus:ring-blue-500
                  dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" 
                placeholder="Örn: Yılmaz" 
                value={formData.lastName} 
                onChange={e => setFormData({...formData, lastName: e.target.value})} 
                required 
              />
            </div>
          </div>

          <div>
             <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Pozisyon / Görev</label>
             <input 
                className="w-full border p-3 rounded-lg outline-none focus:ring-2 transition-colors
                  border-gray-300 text-gray-900 focus:ring-blue-500
                  dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" 
                placeholder="Örn: Usta, Kalfa..." 
                value={formData.role} 
                onChange={e => setFormData({...formData, role: e.target.value})} 
                required 
             />
          </div>

          <div>
             <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Maaş</label>
             <div className="relative">
                <input 
                  type="number"
                  className="w-full border p-3 rounded-lg pl-10 outline-none focus:ring-2 transition-colors
                    border-gray-300 text-gray-900 focus:ring-blue-500
                    dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" 
                  placeholder="0.00" 
                  value={formData.salary} 
                  onChange={e => setFormData({...formData, salary: e.target.value})} 
                  required 
                />
                <DollarSign className="absolute left-3 top-3.5 text-gray-400" size={18}/>
             </div>
          </div>

          <button type="submit" className="w-full py-3 rounded-lg font-bold flex justify-center items-center gap-2 shadow-lg transition-all
            bg-blue-600 text-white hover:bg-blue-700 shadow-blue-200
            dark:bg-brand dark:text-white dark:hover:bg-brand-dark dark:shadow-brand/20">
            <Save size={18} /> Kaydet
          </button>
        </form>
      </div>
    </div>
  );
};

// --- PERSONEL DETAY MODALI ---
export const StaffDetailModal = ({ person, orders, onClose }) => {
  const staffOrders = orders.filter(o => o.personnelIds && o.personnelIds.includes(person.id));
  const totalRevenue = staffOrders.reduce((sum, o) => sum + (o.totalPrice || 0), 0);
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4 backdrop-blur-sm animate-in fade-in">
      <div className="w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh] transition-colors
        bg-white dark:bg-dark-card dark:border dark:border-dark-border">
        <div className="p-6 text-white flex justify-between items-start transition-colors
          bg-gradient-to-r from-blue-600 to-indigo-700
          dark:from-brand-dark dark:to-brand">
          <div>
             <h2 className="text-2xl font-bold">{person.name}</h2>
             <p className="opacity-90 flex items-center gap-2 mt-1"><Briefcase size={16}/> {person.role}</p>
          </div>
          <button onClick={onClose} className="bg-white/20 hover:bg-white/30 p-2 rounded-full transition-colors"><X size={20}/></button>
        </div>

        <div className="p-6 grid grid-cols-3 gap-4 border-b transition-colors
          bg-gray-50 border-gray-200
          dark:bg-dark-bg/50 dark:border-dark-border">
           <div className="text-center">
              <p className="text-xs uppercase font-bold text-gray-500 dark:text-gray-400">Maaş</p>
              <p className="text-xl font-bold text-gray-800 dark:text-gray-100">₺{person.salary?.toLocaleString()}</p>
           </div>
           <div className="text-center border-l border-gray-200 dark:border-dark-border">
              <p className="text-xs uppercase font-bold text-gray-500 dark:text-gray-400">Tamamlanan İş</p>
              <p className="text-xl font-bold text-blue-600 dark:text-brand">{staffOrders.length}</p>
           </div>
           <div className="text-center border-l border-gray-200 dark:border-dark-border">
              <p className="text-xs uppercase font-bold text-gray-500 dark:text-gray-400">Katkı Sağladığı Ciro</p>
              <p className="text-xl font-bold text-green-600 dark:text-green-500">₺{totalRevenue.toLocaleString()}</p>
           </div>
        </div>

        <div className="flex-1 p-6 overflow-y-auto">
           <h4 className="font-bold mb-3 flex items-center gap-2 text-gray-700 dark:text-gray-300"><Calendar size={18}/> İş Geçmişi</h4>
           {staffOrders.length > 0 ? (
             <div className="space-y-2">
               {staffOrders.map(order => (
                 <div key={order.id} className="flex justify-between items-center p-3 border rounded-lg transition-colors
                   bg-white border-gray-200 hover:bg-gray-50
                   dark:bg-dark-bg dark:border-dark-border dark:hover:bg-dark-hover">
                    <div>
                       <span className="font-bold text-gray-800 dark:text-gray-200">{order.plate}</span>
                       <span className="text-sm text-gray-500 dark:text-gray-400 ml-2">{order.vehicle}</span>
                    </div>
                    <div className="text-right">
                       <div className="font-bold text-green-600 dark:text-green-500">₺{order.totalPrice}</div>
                       <div className="text-xs text-gray-400">{order.date}</div>
                    </div>
                 </div>
               ))}
             </div>
           ) : (
             <p className="text-gray-400 italic text-center py-4">Henüz bir iş kaydı bulunmuyor.</p>
           )}
        </div>
      </div>
    </div>
  );
};
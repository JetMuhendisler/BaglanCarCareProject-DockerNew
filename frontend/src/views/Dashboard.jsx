import React, { useState, useEffect, useCallback } from "react";
import { Car, LogOut, ClipboardList, Check, Clock, TrendingUp, Users, DollarSign, Plus, Search, ChevronDown, ChevronRight, Trash2, Settings, Loader2, AlertTriangle, Tag, UserCheck, Moon, Sun, Phone, Calendar } from "lucide-react";

import NewOrderWizard from "./NewOrderWizard"; 
import CalendarView from "../components/CalendarView";
import OrderDetailModal from "../components/OrderDetailModal";
import { StaffDetailModal, AddStaffModal } from "../components/StaffModals";
import AddTransactionModal from "../components/TransactionModal";
import SettingsView from "../components/SettingsView"; 
 
import { orderService, personnelService, expenseService, authService, deletionRequestService } from "../api";
import bgImage from "../assets/bg.jpg";

const safeDate = (dateString) => {
  if (!dateString) return "";
  try { const d = new Date(dateString); return isNaN(d.getTime()) ? dateString : d.toLocaleDateString('tr-TR'); } catch { return dateString; }
};

// --- İŞ EMİRLERİ LİSTESİ (GÜNCELLENDİ: KANBAN & İSTATİSTİK) ---
const OrderList = ({ orders, onEdit, onDelete }) => {
  const [search, setSearch] = useState("");
  const [expandedOrderId, setExpandedOrderId] = useState(null);
  const [viewMode, setViewMode] = useState("list"); // 'list' | 'board'

  const filtered = orders.filter(o => 
    (o.plate || "").toLowerCase().includes(search.toLowerCase()) || 
    (o.customer || "").toLowerCase().includes(search.toLowerCase()) ||
    (o.phone || "").includes(search)
  );

  const toggleExpand = (id) => setExpandedOrderId(expandedOrderId === id ? null : id);



  return (
    <div className="space-y-6">
      
      {/* ARAÇ ÇUBUĞU */}
      <div className="flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="relative w-full md:w-1/3">
            <Search className="absolute left-3 top-2.5 text-gray-400" size={18}/>
            <input className="pl-10 border p-2 rounded-lg w-full outline-none transition-colors
            bg-white text-gray-900 border-gray-300 focus:ring-blue-500
            dark:bg-dark-card dark:text-white dark:border-dark-border dark:focus:ring-brand dark:placeholder-gray-500" 
            placeholder="Plaka veya Müşteri Ara..." value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        
        {/* Görünüm Değiştirici */}
        <div className="flex bg-gray-100 dark:bg-dark-card p-1 rounded-lg border border-gray-200 dark:border-dark-border">
            <button onClick={() => setViewMode("list")} className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${viewMode === "list" ? "bg-white dark:bg-dark-bg shadow-sm text-blue-600 dark:text-brand" : "text-gray-500 hover:text-gray-700 dark:text-gray-400"}`}>
                <ClipboardList size={16}/> Liste
            </button>
            <button onClick={() => setViewMode("board")} className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${viewMode === "board" ? "bg-white dark:bg-dark-bg shadow-sm text-blue-600 dark:text-brand" : "text-gray-500 hover:text-gray-700 dark:text-gray-400"}`}>
                <Tag size={16}/> Pano
            </button>
        </div>
      </div>
      
      {/* LİSTE GÖRÜNÜMÜ */}
      {viewMode === "list" && (
          <div className="space-y-3">
            {filtered.map(order => (
              <div key={order.id} className="border rounded-lg transition-all overflow-hidden shadow-sm
                bg-white border-gray-200 hover:border-blue-400
                dark:bg-dark-card dark:border-dark-border dark:hover:border-brand/50">
                {/* ÖZET KISMI */}
                <div className="p-4 flex flex-col md:flex-row gap-4 md:items-center justify-between cursor-pointer transition-colors
                  hover:bg-gray-50
                  dark:hover:bg-dark-hover" onClick={() => toggleExpand(order.id)}>
                  <div className="flex items-center gap-4">
                    <div className={`p-2 rounded-full transition-colors ${expandedOrderId === order.id 
                      ? "bg-blue-600 dark:bg-brand text-white" 
                      : "bg-gray-100 dark:bg-dark-hover text-gray-500 dark:text-gray-400"}`}>
                      {expandedOrderId === order.id ? <ChevronDown size={20}/> : <ChevronRight size={20}/>}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-lg tracking-wide text-gray-800 dark:text-gray-100">{order.plate}</span>
                        <span className="text-gray-400">|</span>
                        <span className="font-medium text-gray-700 dark:text-gray-300">{order.customer}</span>
                        {order.phone && (
                          <>
                            <span className="text-gray-400 hidden md:inline">|</span>
                            <a href={`tel:${order.phone}`} onClick={(e) => e.stopPropagation()} className="hidden md:flex items-center gap-1 text-sm text-gray-500 hover:text-blue-600 dark:text-gray-400 dark:hover:text-blue-400">
                              <Phone size={14} /> {order.phone}
                            </a>
                          </>
                        )}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1 flex gap-2 items-center">
                        <Car size={12}/> 
                        <span className="font-medium">
                          {[order.brand, order.model, order.year].filter(Boolean).join(" ") || order.vehicle}
                        </span> 
                        <span className="px-1 rounded border dark:bg-dark-hover dark:border-dark-border bg-gray-100 border-gray-200">#{order.id}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 justify-between md:justify-end pl-12 md:pl-0 border-t md:border-t-0 pt-3 md:pt-0 mt-3 md:mt-0">
                     <span className={`px-3 py-1 rounded-full text-xs font-bold border ${(() => {
                        const s = (order.status || "").toLowerCase();
                        if(s.includes("işlemde") || s.includes("progress")) return "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-800";
                        if(s.includes("tamam") || s.includes("completed")) return "bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800";
                        if(s.includes("iptal") || s.includes("cancel")) return "bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800";
                        return "bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-800"; 
                     })()}`}>{order.status}</span>
                    <span className="font-bold text-lg text-gray-800 dark:text-gray-100">₺{order.totalPrice?.toLocaleString()}</span>
                    <div className="flex gap-1 pl-2 border-l border-gray-200 dark:border-dark-border" onClick={(e) => e.stopPropagation()}>
                       <button onClick={() => onEdit(order)} className="p-2 rounded-lg transition-colors text-gray-400 hover:bg-gray-100 hover:text-blue-600 dark:hover:bg-dark-hover dark:hover:text-brand"><Settings size={18}/></button>
                       <button onClick={() => onDelete(order.id)} className="p-2 rounded-lg transition-colors text-gray-400 hover:bg-gray-100 hover:text-red-600 dark:hover:bg-dark-hover dark:hover:text-red-400"><Trash2 size={18}/></button>
                    </div>
                  </div>
                </div>

                {/* DETAY KISMI */}
                {expandedOrderId === order.id && (
                  <div className="p-4 border-t pl-4 md:pl-16 animate-in slide-in-from-top-2 duration-200
                    bg-gray-50 border-gray-200
                    dark:bg-dark-bg/50 dark:border-dark-border">
                    {/* ... (Detay kodu aynı) ... */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6 p-4 rounded-lg bg-white border border-gray-200 dark:bg-dark-card dark:border-dark-border">
                      <div>
                        <h5 className="text-xs font-bold text-gray-400 uppercase mb-2">Müşteri Bilgileri</h5>
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <Users size={16} className="text-blue-500"/>
                            <span className="font-medium text-gray-800 dark:text-gray-200">{order.customer}</span>
                          </div>
                          {order.phone && (
                            <div className="flex items-center gap-2">
                              <Phone size={16} className="text-green-500"/>
                              <a href={`tel:${order.phone}`} className="text-gray-600 hover:text-blue-600 dark:text-gray-400 dark:hover:text-blue-400">{order.phone}</a>
                            </div>
                          )}
                          {order.email && <div className="text-gray-500 text-sm ml-6">{order.email}</div>}
                        </div>
                      </div>
                      <div>
                        <h5 className="text-xs font-bold text-gray-400 uppercase mb-2">Araç Bilgileri</h5>
                        <div className="grid grid-cols-2 gap-y-1 gap-x-4 text-sm">
                           <div className="text-gray-500">Plaka:</div> <div className="font-mono font-bold text-gray-800 dark:text-gray-200">{order.plate}</div>
                           <div className="text-gray-500">Marka/Model:</div> <div className="font-medium text-gray-800 dark:text-gray-200">{[order.brand, order.model].filter(Boolean).join(" ") || order.vehicle || "-"}</div>
                        </div>
                      </div>
                    </div>
                    
                    {/* Hizmetler ve Alt Bilgi (Aynı) */}
                     <h4 className="text-xs font-bold text-gray-500 uppercase mb-3 flex items-center gap-2"><Tag size={14}/> Yapılacak İşlemler</h4>
                     {order.services && order.services.length > 0 ? (
                        <div className="space-y-2 mb-4">
                            {order.services.map((s,i) => (
                                <div key={i} className="flex justify-between p-2 rounded bg-white border border-gray-200 dark:bg-dark-card dark:border-dark-border">
                                    <span className="text-sm">{s.product || s.Product}</span>
                                    <span className="font-bold text-sm">₺{s.price || s.Price}</span>
                                </div>
                            ))}
                        </div>
                     ) : <div className="text-gray-500 italic text-sm mb-4">Hizmet yok.</div>}

                     <div className="flex justify-end pt-3 border-t border-gray-200 dark:border-dark-border">
                        <span className="font-bold text-blue-600 dark:text-brand">{order.assignedStaff}</span>
                     </div>
                  </div>
                )}
              </div>
            ))}
            {filtered.length === 0 && <div className="text-center text-gray-500 py-10">Kayıt bulunamadı.</div>}
          </div>
      )}

      {/* PANO (BOARD) GÖRÜNÜMÜ */}
      {viewMode === "board" && (
         <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-[calc(100vh-250px)] overflow-x-auto">
            {/* SÜTUNLAR */}
            {[
                { title: "Bekliyor", statusKey: "bekliyor", color: "bg-orange-50 border-orange-200 dark:bg-orange-900/10 dark:border-orange-800" },
                { title: "İşlemde", statusKey: "işlemde", color: "bg-blue-50 border-blue-200 dark:bg-blue-900/10 dark:border-blue-800" },
                { title: "Tamamlandı", statusKey: "tamam", color: "bg-green-50 border-green-200 dark:bg-green-900/10 dark:border-green-800" }
            ].map(col => (
                <div key={col.statusKey} className={`flex flex-col h-full rounded-xl border ${col.color}`}>
                    <div className="p-4 border-b border-gray-200/50 dark:border-dark-border/50 flex justify-between items-center">
                        <h3 className="font-bold text-gray-800 dark:text-gray-100">{col.title}</h3>
                        <span className="px-2 py-0.5 rounded-full bg-white dark:bg-dark-bg text-xs font-bold shadow-sm">
                            {filtered.filter(o => (o.status || "").toLowerCase().includes(col.statusKey)).length}
                        </span>
                    </div>
                    <div className="flex-1 overflow-y-auto p-3 space-y-3">
                        {filtered.filter(o => (o.status || "").toLowerCase().includes(col.statusKey)).map(order => (
                            <div key={order.id} onClick={() => onEdit(order)} className="bg-white dark:bg-dark-card p-3 rounded-lg shadow-sm border border-gray-200 dark:border-dark-border hover:shadow-md cursor-pointer transition-all group">
                                <div className="flex justify-between items-start mb-2">
                                    <span className="font-mono font-bold text-gray-800 dark:text-gray-100">{order.plate}</span>
                                    <span className="text-xs font-bold text-gray-500">#{order.id}</span>
                                </div>
                                <p className="text-sm text-gray-600 dark:text-gray-400 mb-2 truncate">{order.customer}</p>
                                <div className="flex justify-between items-center text-xs text-gray-500">
                                    <span>{order.vehicle}</span>
                                    <span className="font-bold text-blue-600 dark:text-brand">₺{order.totalPrice?.toLocaleString()}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            ))}
         </div>
      )}

    </div>
  );
};

// --- DASHBOARD CONTAINER ---
const Dashboard = ({ user, onLogout }) => {
  const [activeTab, setActiveTab] = useState("orders");
  const [orders, setOrders] = useState([]);
  const [staff, setStaff] = useState([]);
  const [expenses, setExpenses] = useState([]);
  const [users, setUsers] = useState([]);
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const [showAddUser, setShowAddUser] = useState(false);
  const [calendarSelectedDate, setCalendarSelectedDate] = useState(new Date().toISOString().split("T")[0]); // Takvim için varsayılan bugün // Kullanıcı ekleme modalı
  const [newUser, setNewUser] = useState({ username: "", password: "", fullName: "", role: "Staff" }); // Yeni kullanıcı formu

  const [showWizard, setShowWizard] = useState(false);
  const [showOrderDetail, setShowOrderDetail] = useState(null);
  const [showStaffDetail, setShowStaffDetail] = useState(null);
  const [showAddStaff, setShowAddStaff] = useState(false);
  const [showAddExpense, setShowAddExpense] = useState(false);

  // --- DARK MODE TOGGLE ---
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    // İlk Yükleme: Kaydedilmiş mi bak, yoksa varsayılan Dark
    const saved = localStorage.getItem("theme");
    if (saved === "light") {
        setIsDark(false);
        document.documentElement.classList.remove("dark");
    } else {
        setIsDark(true);
        document.documentElement.classList.add("dark");
    }
  }, []);

  const toggleTheme = () => {
    if (isDark) {
        document.documentElement.classList.remove("dark");
        localStorage.setItem("theme", "light");
        setIsDark(false);
    } else {
        document.documentElement.classList.add("dark");
        localStorage.setItem("theme", "dark");
        setIsDark(true);
    }
  };

  const fetchData = useCallback(async () => {
    if (!user) return;
    setLoading(true);
    setErrorMsg(null);
    try {
      // SİPARİŞLERİ AL
      const ordersData = await orderService.getAll();
      setOrders(Array.isArray(ordersData) ? ordersData.map(o => ({
        id: o.id || o.Id,
        customer: o.customerInfo || o.CustomerInfo || o.customerName || "Misafir",
        phone: o.CustomerPhone || o.customerPhone || o.Phone || o.phone || "",
        email: o.CustomerEmail || o.customerEmail || o.Email || o.email || "",
        brand: o.Brand || o.brand || "",
        model: o.Model || o.model || "",
        color: (o.Color || o.color || "").toString().trim() || "-",
        year: (o.Year || o.year || "").toString().trim() || "-",
        vehicle: o.vehicleInfo || o.VehicleInfo || "Araç Yok",
        plate: o.VehiclePlate || o.vehiclePlate || o.Plate || o.plate || "---",
        status: o.StatusTr || o.statusTr || o.Status || "Bekliyor",
        date: safeDate(o.Date || o.date || o.TransactionDate),
        rawDate: o.Date || o.date || o.TransactionDate, // CalendarView için ham tarih gerekli
        totalPrice: o.TotalPrice || o.totalPrice || 0,
        services: o.selectedServices || o.SelectedServices || o.SummaryList || [], 
        paymentMethod: o.PaymentMethod || o.paymentMethod || "Nakit",
        isPaid: o.IsPaid || o.isPaid,
        personnelIds: o.PersonnelIds || o.personnelIds || [],
        
        // --- PERSONEL İSMİNİ BURADAN ALIYORUZ ---
        assignedStaff: o.PersonnelNames || o.personnelNames || "Atanmadı", 
        
      })).sort((a, b) => b.id - a.id) : []);

      // PERSONEL VE MUHASEBE
      // 2. Personel Verisi (DÜZELTİLDİ)
      const staffData = await personnelService.getAll();
      
      // Backend'den gelen veri yapısı: { id: 1, fullName: "Ali Veli", ... }
      // Bizim Frontend'in beklediği: { id: 1, name: "Ali Veli", ... }
      
      setStaff(Array.isArray(staffData) ? staffData.map(p => ({
        id: p.id || p.Id,
        
        // KRİTİK DÜZELTME: Backend 'fullName' gönderiyor, onu alıyoruz.
        name: p.fullName || p.FullName || p.Name || "İsimsiz", 
        
        role: p.position || p.Position || "Personel", // Backend 'position' gönderiyor
        salary: p.salary || p.Salary || 0,
      })).sort((a, b) => b.id - a.id) : []);
      const expensesData = await expenseService.getAll();
      setExpenses(Array.isArray(expensesData) ? expensesData.map(e => ({
        id: e.id || e.Id,
        type: (e.Type === 1 || e.type === 1 || e.IsIncome === true) ? "income" : "expense",
        title: e.Title || e.title || e.Description || e.description,
        description: e.Description || e.description,
        amount: e.Amount || e.amount || 0,
        date: safeDate(e.Date || e.date),
        category: e.Category || e.category || ((e.Type === 1 || e.type === 1) ? "Gelir" : "Gider")
      })).sort((a, b) => b.id - a.id) : []);

      // ADMIN ÖZEL VERİLERİ (Kullanıcılar ve Silme Talepleri)
      if (user && user.role === "Admin") {
          try {
             const usersData = await authService.getUsers();
             setUsers(Array.isArray(usersData) ? usersData : []);
             
             const reqData = await deletionRequestService.getPending();
             setRequests(Array.isArray(reqData) ? reqData : []);
          } catch (e) {
              console.warn("Admin verileri çekilemedi", e);
          }
      }

    } catch (error) {
      console.error("Veri çekme hatası:", error);
      setErrorMsg("Veriler yüklenirken hata oluştu.");
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Yardımcılar
  const handleDeleteOrder = async (id) => { 
      let note = "";
      if (user.role !== "Admin") {
          note = prompt("Silme sebebi nedir?");
          if (note === null) return; // İptal
          if (!note.trim()) { alert("Silme sebebi girmelisiniz."); return; }
      } else {
          if (!confirm("Silinsin mi?")) return;
      }
      try {
          // Note backend'e gönderilecek (Admin ise zaten direkt siler, note göz ardı edilir veya loglanır)
          await orderService.delete(id, note); 
          fetchData(); 
          if(user.role !== "Admin") alert("Silme talebi oluşturuldu."); 
      } catch(e) { alert("Hata: " + e.message); }
  };
  
  const handleDeleteStaff = async (id) => { if (confirm("Silinsin mi?")) { await personnelService.delete(id); fetchData(); } };
  const handleDeleteExpense = async (id) => { if (confirm("Silinsin mi?")) { await expenseService.delete(id); fetchData(); } };
  const handleAddStaff = async (data) => {
    try {
      // Artık Ad ve Soyad ayrı geliyor, split yapmaya gerek yok.
      await personnelService.create({ 
        firstName: data.firstName, 
        lastName: data.lastName, 
        position: data.role, 
        salary: parseFloat(data.salary), 
        startDate: new Date().toISOString() 
      });
      
      setShowAddStaff(false); // Modalı kapat
      fetchData(); // Listeyi yenile
    } catch (err) {
      alert("Personel eklenirken hata oluştu: " + err.message);
    }
  };
  const handleAddExpense = async (d) => { await expenseService.create({...d, amount: parseFloat(d.amount), type: d.type==="income"?1:0}); setShowAddExpense(false); fetchData(); };
  
  // --- ADMIN FONKSİYONLARI ---
  const handleAddUser = async (e) => {
    e.preventDefault();
    try {
      await authService.register(newUser);
      setShowAddUser(false);
      setNewUser({ username: "", password: "", fullName: "", role: "Staff" });
      fetchData();
      alert("Kullanıcı oluşturuldu!");
    } catch (err) {
      alert("Hata: " + (err.response?.data?.Message || err.message));
    }
  };

  const handleApproveRequest = async (id) => {
    if(!confirm("Bu silme işlemini onaylıyor musunuz?")) return;
    try { await deletionRequestService.approve(id); fetchData(); } catch(err) { alert("Hata: " + err.message); }
  };

  const handleRejectRequest = async (id) => {
    if(!confirm("Bu silme işlemini reddediyor musunuz?")) return;
    try { await deletionRequestService.reject(id); fetchData(); } catch(err) { alert("Hata: " + err.message); }
  };

  const stats = {
    totalOrders: orders.length,
    completedOrders: orders.filter(o => (o.status || "").toLowerCase().includes("tamam") || (o.status || "").toLowerCase().includes("completed")).length,
    pendingOrders: orders.filter(o => (o.status || "").toLowerCase().includes("bekliyor") || (o.status || "").toLowerCase().includes("pending")).length,
    totalRevenue: orders.reduce((sum, o) => sum + (o.totalPrice || 0), 0) // Ciro her zaman toplam işlem tutarıdır, sadece tamamlananlar değil. İsteğe göre değişebilir ama genelde toplam iş hacmi gösterilir. DEĞİŞİKLİK: Kullanıcı "Ciro 0" dedi, tamamlanmayanlar da görünsün isteniyor olabilir veya statüler uyuşmuyor. Ben hepsini topluyorum şimdilik.
  };

  const StaffList = ({ staff, onAdd, onDetail, onDelete }) => (
    <div>
      <div className="flex justify-end mb-4">
        <button onClick={onAdd} className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2 shadow-sm">
            <Plus size={18}/> Yeni Personel
        </button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {staff.map(p => (
          <div key={p.id} className="border p-4 rounded-lg bg-white flex justify-between items-start group hover:shadow-md transition-shadow">
            <div className="flex items-center gap-3 cursor-pointer flex-1" onClick={() => onDetail(p)}>
              <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center text-indigo-700 font-bold uppercase">
                {/* İlk harfi al, yoksa 'U' koy */}
                {p.name ? p.name.charAt(0) : "U"}
              </div>
              <div>
                {/* İSİM BURADA GÖRÜNÜYOR */}
                <h3 className="font-bold text-gray-800">{p.name || "İsimsiz"}</h3>
                <p className="text-xs text-gray-500">{p.role || "Görev Yok"}</p>
                <p className="text-xs text-green-600 font-bold mt-1">₺{p.salary?.toLocaleString()}</p>
              </div>
            </div>
            <button onClick={(e)=>{e.stopPropagation();onDelete(p.id)}} className="text-red-400 hover:text-red-600 p-2 rounded-full hover:bg-red-50">
                <Trash2 size={18}/>
            </button>
          </div>
        ))}
        {staff.length === 0 && <div className="col-span-3 text-center text-gray-400 py-10">Kayıtlı personel bulunamadı.</div>}
      </div>
    </div>
  );

  const AccountingView = ({ expenses, orders, onAdd, onDelete, onDeleteOrder }) => {
    const combinedItems = [...expenses.map(e => ({...e, source:'expense'})), ...orders.filter(o=>(o.status||"").toLowerCase().includes("tamam")||(o.status||"").toLowerCase().includes("completed")).map(o=>({id:o.id, date:o.date, title:`${o.plate} - ${o.customer}`, category:"İş Emri", amount:o.totalPrice, type:"income", source:'order'}))].sort((a,b)=>new Date(b.date)-new Date(a.date));

    // Excel/CSV İndirme Fonksiyonu
    const exportToCSV = () => {
      // BOM ekle (Türkçe karakterler için)
      const BOM = "\uFEFF";
      const headers = ["No", "Tarih", "Açıklama", "Kategori", "Tutar", "Tip"];
      const rows = combinedItems.map(item => [
          item.id,
          safeDate(item.date),
          `"${item.title.replace(/"/g, '""')}"`, // CSV escape
          item.category,
          item.amount,
          item.type === "income" ? "Gelir" : "Gider"
      ]);

      const csvContent = BOM + [
          headers.join(";"),
          ...rows.map(r => r.join(";"))
      ].join("\n");

      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `Muhasebe_Raporu_${new Date().toLocaleDateString()}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    };

    return (
      <div>
        <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-bold">Gelir / Gider</h2>
            <div className="flex gap-2">
                <button onClick={exportToCSV} className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 flex items-center gap-2 text-sm">
                    <ClipboardList size={18}/> Excel İndir
                </button>
                <button onClick={onAdd} className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2 text-sm">
                    <Plus size={18}/> Yeni Kayıt
                </button>
            </div>
        </div>
        <div className="overflow-x-auto"><table className="w-full text-left"><thead className="bg-gray-50 text-gray-500 text-sm border-b"><tr>{["No","Tarih","Açıklama","Kategori","Tutar",""].map(h=><th key={h} className="p-3">{h}</th>)}</tr></thead><tbody className="divide-y text-sm">{combinedItems.map((item,idx)=>(<tr key={`${item.source}-${item.id}-${idx}`} className="hover:bg-gray-50"><td className="p-3 font-mono text-gray-400">#{item.id}</td><td className="p-3 text-gray-600">{item.date}</td><td className="p-3 font-medium">{item.title}</td><td className="p-3"><span className={`px-2 py-1 rounded text-xs ${item.type==="income"?"bg-green-100 text-green-800":"bg-red-100 text-red-800"}`}>{item.category}</span></td><td className={`p-3 font-bold ${item.type==="income"?"text-green-600":"text-red-600"}`}>{item.type==="income"?"+":"-"}₺{item.amount?.toLocaleString()}</td><td className="p-3 text-right"><button onClick={()=>item.source==='order'?onDeleteOrder(item.id):onDelete(item.id)} className="text-red-400 hover:text-red-600"><Trash2 size={16}/></button></td></tr>))}</tbody></table></div>
      </div>
    );
  };

  // Kullanıcı Silme
  const handleDeleteUser = async (id) => {
    if(!confirm("Bu kullanıcıyı silmek istediğinize emin misiniz?")) return;
    try {
        await authService.deleteUser(id);
        fetchData(); // Listeyi yenile
    } catch(err) {
        alert("Hata: " + (err.response?.data?.Message || err.message));
    }
  };

  return (
    <div 
      className="min-h-screen font-sans transition-colors duration-300
      bg-gray-100 text-gray-800
      dark:bg-dark-bg dark:text-gray-200"
    >
      {/* ... (Header kısmı aynı) ... */}
      <div className="shadow-sm border-b transition-colors bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">
          <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
            <div className="flex items-center gap-3">
                <img src={bgImage} alt="Logo" className="w-12 h-12 object-contain rounded-lg shadow-sm bg-white border border-gray-100 dark:border-dark-border" />
                <div><h1 className="text-xl font-bold text-gray-800 dark:text-gray-100">Bağlan Oto Care</h1><p className="text-sm text-gray-500 dark:text-gray-400">Yönetim Paneli</p></div>
            </div>
            <div className="flex items-center gap-4">
                <button onClick={toggleTheme} className="p-2 rounded-full transition-colors bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-dark-hover dark:text-brand dark:hover:bg-dark-bg">{isDark ? <Sun size={20}/> : <Moon size={20}/>}</button>
                <div className="h-6 w-px bg-gray-300 dark:bg-gray-600"></div>
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{user?.name}</span>
                <button onClick={onLogout} className="text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"><LogOut size={20}/></button>
            </div>
          </div>
      </div>
      {/* ... */}

      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="p-6 rounded-lg shadow flex justify-between border bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">
              <div><p className="text-gray-500 dark:text-gray-400 text-sm">Toplam İş</p><p className="text-2xl font-bold text-gray-800 dark:text-white">{stats.totalOrders}</p></div>
              <ClipboardList className="text-blue-500 dark:text-brand" size={32}/>
          </div>
          <div className="p-6 rounded-lg shadow flex justify-between border bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">
              <div><p className="text-gray-500 dark:text-gray-400 text-sm">Tamamlanan</p><p className="text-2xl font-bold text-green-600 dark:text-green-400">{stats.completedOrders}</p></div>
              <Check className="text-green-500 dark:text-green-400" size={32}/>
          </div>
          <div className="p-6 rounded-lg shadow flex justify-between border bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">
              <div><p className="text-gray-500 dark:text-gray-400 text-sm">Bekleyen</p><p className="text-2xl font-bold text-yellow-600 dark:text-yellow-500">{stats.pendingOrders}</p></div>
              <Clock className="text-yellow-500" size={32}/>
          </div>
          <div className="p-6 rounded-lg shadow flex justify-between border bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">
              <div><p className="text-gray-500 dark:text-gray-400 text-sm">Ciro</p><p className="text-2xl font-bold text-blue-700 dark:text-brand-accent">₺{stats.totalRevenue?.toLocaleString()}</p></div>
              <TrendingUp className="text-blue-600 dark:text-brand-accent" size={32}/>
          </div>
        </div>
        <div className="bg-gray-100 dark:bg-dark-card p-1 rounded-xl flex gap-1 overflow-x-auto mb-4 border border-gray-200 dark:border-dark-border">
          {(() => {
             const tabs = [
                { id: "orders", label: "İş Emirleri", icon: ClipboardList },
                { id: "calendar", label: "Takvim", icon: Calendar },
                { id: "customers", label: "Müşteri Ekle", icon: Plus },
                { id: "staff", label: "Personel", icon: Users },
                { id: "accounting", label: "Muhasebe", icon: DollarSign }
             ];
             if(user?.role === "Admin"){ 
                 tabs.push({ id: "settings", label: "Ayarlar", icon: Settings });
                 tabs.push({ id: "users", label: "Kullanıcılar", icon: UserCheck });
                 tabs.push({ id: "requests", label: "Talepler", icon: AlertTriangle });
             }

             return tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => tab.id === "customers" ? setShowWizard(true) : setActiveTab(tab.id)}
                  className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 whitespace-nowrap
                  ${activeTab === tab.id
                      ? "bg-white dark:bg-dark-bg text-blue-600 dark:text-brand shadow-sm ring-1 ring-black/5 dark:ring-white/10"
                      : "text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-white/50 dark:hover:bg-white/5"}`}
                >
                  <tab.icon size={18} /> {tab.label}
                  {tab.id === "requests" && requests.length > 0 && <span className="text-[10px] bg-red-500 text-white px-1.5 py-0.5 rounded-full ml-1">{requests.length}</span>}
                </button>
              ));
          })()}
        </div>
        <div className="rounded-lg shadow p-6 min-h-[400px] border bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">
          {errorMsg && <div className="bg-red-900/20 text-red-300 border border-red-900/50 p-3 rounded mb-4 flex items-center gap-2"><AlertTriangle size={18}/>{errorMsg}</div>}
          {loading ? <div className="flex justify-center items-center h-64"><Loader2 className="animate-spin text-brand" size={48}/></div> : (
            <>
              {activeTab === "orders" && <OrderList orders={orders} onEdit={(o) => setShowOrderDetail(o)} onDelete={handleDeleteOrder} />}
              {activeTab === "calendar" && (
                <div className="animate-fade-in flex flex-col md:flex-row gap-6 h-[calc(100vh-200px)]">
                    {/* LEFT: CALENDAR */}
                    <div className="flex-1 flex flex-col bg-white dark:bg-dark-card rounded-xl border border-gray-200 dark:border-dark-border p-4 shadow-sm overflow-hidden">
                        <CalendarView 
                            orders={orders} 
                            selectedDate={calendarSelectedDate} 
                            onDateSelect={(d) => setCalendarSelectedDate(d)} 
                            showDetails={false} 
                        />
                    </div>

                    {/* RIGHT: DETAILS */}
                    <div className="w-full md:w-96 flex flex-col bg-white dark:bg-dark-card rounded-xl border border-gray-200 dark:border-dark-border p-4 shadow-sm">
                        <h3 className="font-bold text-lg mb-4 flex items-center gap-2 border-b pb-2 dark:border-dark-border">
                            <Calendar size={20} className="text-blue-600 dark:text-brand"/> 
                            {new Date(calendarSelectedDate).toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', weekday: 'long' })}
                        </h3>
                        
                        <div className="flex-1 overflow-y-auto space-y-3 pr-1 custom-scrollbar">
                            {(() => {
                                const dayOrders = orders.filter(o => {
                                    const oDate = new Date(o.rawDate || o.date || o.Date || o.TransactionDate);
                                    return !isNaN(oDate.getTime()) && oDate.toISOString().split('T')[0] === calendarSelectedDate;
                                });

                                if (dayOrders.length === 0) return (
                                    <div className="flex flex-col items-center justify-center h-full text-gray-400 opacity-70">
                                        <Calendar size={48} strokeWidth={1} className="mb-2"/>
                                        <span>Bu tarihte planlanmış işlem yok.</span>
                                    </div>
                                );

                                return dayOrders.map(o => (
                                    <div key={o.id} onClick={() => { setSelectedOrder(o); setShowOrderDetail(true); }} 
                                        className="p-3 rounded-lg border border-gray-100 dark:border-dark-border hover:border-blue-300 dark:hover:border-brand cursor-pointer group transition-all bg-gray-50 dark:bg-dark-bg/50">
                                        <div className="flex justify-between items-start mb-2">
                                            <span className="font-bold text-lg group-hover:text-blue-600 dark:group-hover:text-brand transition-colors">{o.plate}</span>
                                            <span className={`text-[10px] px-2 py-0.5 rounded-full border
                                                ${(o.status||"").includes("Bekliyor") ? "bg-orange-100 text-orange-700 border-orange-200" : 
                                                  (o.status||"").includes("Tamam") ? "bg-green-100 text-green-700 border-green-200" : 
                                                  "bg-blue-100 text-blue-700 border-blue-200"}`}>{o.status}</span>
                                        </div>
                                        <div className="text-sm text-gray-600 dark:text-gray-400 mb-1">{o.brand} {o.model}</div>
                                        <div className="flex items-center gap-2 text-xs text-gray-400">
                                            <User size={12}/> {o.customer}
                                        </div>
                                    </div>
                                ));
                            })()}
                        </div>
                    </div>
                </div>
              )}
              {activeTab === "staff" && <StaffList staff={staff} onAdd={() => setShowAddStaff(true)} onDetail={(p) => setShowStaffDetail(p)} onDelete={handleDeleteStaff} />}
              {activeTab === "accounting" && <AccountingView expenses={expenses} orders={orders} onAdd={() => setShowAddExpense(true)} onDelete={handleDeleteExpense} onDeleteOrder={handleDeleteOrder} />}
              {activeTab === "settings" && <SettingsView />}
              
              {/* KULLANICILAR TABLOSU */}
              {activeTab === "users" && (
                <div>
                  <div className="flex justify-between items-center mb-4">
                    <h2 className="text-lg font-bold">Yetkili Kullanıcılar</h2>
                    <button onClick={() => setShowAddUser(true)} className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2"><Plus size={18} /> Yeni Kullanıcı</button>
                  </div>
                  <table className="w-full text-left">
                    <thead className="bg-gray-50 dark:bg-dark-hover text-gray-500 text-sm border-b">
                        <tr><th className="p-3">ID</th><th className="p-3">Kullanıcı Adı</th><th className="p-3">Tam İsim</th><th className="p-3">Rol</th><th className="p-3"></th></tr>
                    </thead>
                    <tbody className="divide-y text-sm">
                      {users.map(u => (
                        <tr key={u.id} className="hover:bg-gray-50 dark:hover:bg-dark-hover">
                          <td className="p-3">#{u.id}</td>
                          <td className="p-3 font-bold">{u.username}</td>
                          <td className="p-3">{u.fullName}</td>
                          <td className="p-3"><span className={`px-2 py-1 rounded text-xs ${u.role === "Admin" ? "bg-red-100 text-red-800" : "bg-blue-100 text-blue-800"}`}>{u.role}</span></td>
                          <td className="p-3 text-right">
                              {/* Admin kendini silemesin diye basit kontrol (opsiyonel) -> id !== user.id */}
                              <button onClick={() => handleDeleteUser(u.id)} className="text-red-400 hover:text-red-600 p-1"><Trash2 size={16}/></button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* TALEPLER TABLOSU */}
              {activeTab === "requests" && (
                <div>
                   <h2 className="text-lg font-bold mb-4">Silme Talepleri</h2>
                   {requests.length === 0 ? <p className="text-gray-500">Bekleyen talep yok.</p> : (
                     <div className="space-y-3">
                       {requests.map(r => (
                         <div key={r.id} className="border p-4 rounded-lg flex justify-between items-center bg-gray-50 dark:bg-dark-hover">
                            <div>
                               <p className="font-bold text-red-600">{r.requesterName} bir silme talebi oluşturdu.</p>
                               <p className="text-sm text-gray-600 dark:text-gray-300">Hedef: <span className="font-mono">{r.targetEntityName} #{r.targetId}</span></p>
                               <p className="text-xs text-gray-500 italic">Not: {r.note}</p>
                               <p className="text-xs text-gray-400 mt-1">{new Date(r.requestedDate).toLocaleString()}</p>
                            </div>
                            <div className="flex gap-2">
                               <button onClick={() => handleApproveRequest(r.id)} className="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700">Onayla</button>
                               <button onClick={() => handleRejectRequest(r.id)} className="bg-gray-500 text-white px-3 py-1 rounded text-sm hover:bg-gray-600">Reddet</button>
                            </div>
                         </div>
                       ))}
                     </div>
                   )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
      {showWizard && <NewOrderWizard onClose={()=>setShowWizard(false)} onSuccess={()=>{fetchData();setShowWizard(false)}}/>}
      {showOrderDetail && <OrderDetailModal order={showOrderDetail} staff={staff} onClose={()=>setShowOrderDetail(null)} onSave={()=>{fetchData();setShowOrderDetail(null)}}/>}
      {showStaffDetail && <StaffDetailModal person={showStaffDetail} orders={orders} onClose={() => setShowStaffDetail(null)} />}
      {showAddStaff && <AddStaffModal onClose={() => setShowAddStaff(false)} onAdd={handleAddStaff} />}
      {showAddExpense && <AddTransactionModal onClose={() => setShowAddExpense(false)} onAdd={handleAddExpense} />}

      {/* YENİ KULLANICI MODALI */}
      {showAddUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
           <div className="bg-white dark:bg-dark-card w-full max-w-md rounded-2xl shadow-2xl p-6 relative border border-gray-200 dark:border-dark-border">
              <h2 className="text-xl font-bold mb-4 text-gray-800 dark:text-white">Yeni Yetkili Kullanıcı</h2>
              <form onSubmit={handleAddUser} className="space-y-4">
                 <div>
                    <label className="block text-sm font-medium mb-1 dark:text-gray-300">Kullanıcı Adı</label>
                    <input required className="w-full border p-2 rounded bg-gray-50 dark:bg-dark-bg dark:border-dark-border dark:text-white" value={newUser.username} onChange={e => setNewUser({...newUser, username: e.target.value})} />
                 </div>
                 <div>
                    <label className="block text-sm font-medium mb-1 dark:text-gray-300">Şifre</label>
                    <input required type="password" className="w-full border p-2 rounded bg-gray-50 dark:bg-dark-bg dark:border-dark-border dark:text-white" value={newUser.password} onChange={e => setNewUser({...newUser, password: e.target.value})} />
                 </div>
                 <div>
                    <label className="block text-sm font-medium mb-1 dark:text-gray-300">Ad Soyad</label>
                    <input required className="w-full border p-2 rounded bg-gray-50 dark:bg-dark-bg dark:border-dark-border dark:text-white" value={newUser.fullName} onChange={e => setNewUser({...newUser, fullName: e.target.value})} />
                 </div>
                 <div>
                    <label className="block text-sm font-medium mb-1 dark:text-gray-300">Rol</label>
                    <select className="w-full border p-2 rounded bg-gray-50 dark:bg-dark-bg dark:border-dark-border dark:text-white" value={newUser.role} onChange={e => setNewUser({...newUser, role: e.target.value})}>
                        <option value="Staff">Personel (Kısıtlı)</option>
                        <option value="Admin">Admin (Tam Yetki)</option>
                    </select>
                 </div>
                 <div className="flex gap-2 justify-end mt-4">
                    <button type="button" onClick={() => setShowAddUser(false)} className="px-4 py-2 rounded bg-gray-200 dark:bg-dark-hover dark:text-gray-300 hover:bg-gray-300">İptal</button>
                    <button type="submit" className="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700">Oluştur</button>
                 </div>
              </form>
           </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
import React, { useState, useEffect, useCallback } from "react";
import { Car, LogOut, ClipboardList, Check, Clock, TrendingUp, Users, DollarSign, Plus, Search, ChevronDown, ChevronRight, Trash2, Settings, Loader2, AlertTriangle, Tag, UserCheck, Moon, Sun } from "lucide-react";

import NewOrderWizard from "./NewOrderWizard"; 
import OrderDetailModal from "../components/OrderDetailModal";
import { StaffDetailModal, AddStaffModal } from "../components/StaffModals";
import AddTransactionModal from "../components/TransactionModal";
import SettingsView from "../components/SettingsView"; 
 
import { orderService, personnelService, expenseService } from "../api";
import bgImage from "../assets/bg.jpg";

const safeDate = (dateString) => {
  if (!dateString) return "";
  try { const d = new Date(dateString); return isNaN(d.getTime()) ? dateString : d.toLocaleDateString('tr-TR'); } catch { return dateString; }
};

// --- İŞ EMİRLERİ LİSTESİ (GÜNCELLENDİ) ---
const OrderList = ({ orders, onEdit, onDelete }) => {
  const [search, setSearch] = useState("");
  const [expandedOrderId, setExpandedOrderId] = useState(null);

  const filtered = orders.filter(o => 
    (o.plate || "").toLowerCase().includes(search.toLowerCase()) || 
    (o.customer || "").toLowerCase().includes(search.toLowerCase())
  );

  const toggleExpand = (id) => setExpandedOrderId(expandedOrderId === id ? null : id);

  return (
    <div>
      <div className="mb-4 relative">
        <Search className="absolute left-3 top-2.5 text-gray-400" size={18}/>
        <input className="pl-10 border p-2 rounded-lg w-full md:w-1/3 outline-none transition-colors
          bg-white text-gray-900 border-gray-300 focus:ring-blue-500
          dark:bg-dark-card dark:text-white dark:border-dark-border dark:focus:ring-brand dark:placeholder-gray-500" 
          placeholder="Plaka veya Müşteri Ara..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>
      
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
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400 mt-1 flex gap-2 items-center"><Car size={12}/> {order.vehicle} 
                    <span className="px-1 rounded border dark:bg-dark-hover dark:border-dark-border bg-gray-100 border-gray-200">#{order.id}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-4 justify-between md:justify-end pl-12 md:pl-0 border-t md:border-t-0 pt-3 md:pt-0 mt-3 md:mt-0">
                 <span className={`px-3 py-1 rounded-full text-xs font-bold border ${order.status === "Completed" || order.status === "Tamamlandı" 
                   ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800" 
                   : "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800"}`}>{order.status}</span>
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
                
                {/* 1. Hizmetler */}
                <h4 className="text-xs font-bold text-gray-500 uppercase mb-3 flex items-center gap-2"><Tag size={14}/> Yapılacak İşlemler</h4>
                {order.services && Array.isArray(order.services) && order.services.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
                    {order.services.map((item, idx) => (
                      <div key={idx} className="flex justify-between items-center p-3 rounded-md shadow-sm border
                        bg-white border-gray-200
                        dark:bg-dark-card dark:border-dark-border">
                        <div className="flex flex-col">
                          <span className="font-bold text-sm text-gray-800 dark:text-gray-200">{item.product || item.Product || "Hizmet"}</span>
                          <div className="text-xs mt-1 flex items-center gap-2">
                             {(item.spec || item.Spec) && <span className="px-1.5 py-0.5 rounded font-medium border
                               bg-purple-50 text-purple-700 border-purple-200
                               dark:bg-brand/10 dark:text-brand dark:border-brand/20">{item.spec || item.Spec}</span>}
                             <span className="text-gray-500">{item.category || item.Category}</span>
                             <ChevronRight size={10} className="text-gray-400 dark:text-gray-600"/>
                             <span className="font-bold text-gray-600 dark:text-gray-400">{item.part || item.Part || item.SelectedParts}</span>
                          </div>
                        </div>
                        <span className="font-bold px-2 py-1 rounded text-sm border
                          bg-gray-50 text-gray-800 border-gray-200
                          dark:bg-brand/10 dark:text-brand dark:border-brand/20">₺{item.price || item.Price}</span>
                      </div>
                    ))}
                  </div>
                ) : (<div className="p-3 rounded border text-sm text-gray-500 italic text-center mb-4 bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">Hizmet detayı girilmemiş.</div>)}
                
                {/* 2. Alt Bilgi (Personel & Ödeme) */}
                <div className="pt-3 border-t flex flex-col md:flex-row justify-between text-sm text-gray-600 dark:text-gray-400 gap-2
                  border-gray-200 dark:border-dark-border">
                  
                  {/* PERSONEL GÖSTERİMİ */}
                  <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border w-fit
                    bg-blue-50 border-blue-100
                    dark:bg-blue-900/20 dark:border-blue-800">
                    <UserCheck size={16} className="text-blue-600 dark:text-blue-400"/>
                    <span className="font-bold text-blue-800 dark:text-blue-300">Personel:</span>
                    <span className="text-blue-900 dark:text-blue-200 font-medium">{order.assignedStaff}</span>
                  </div>

                  <div className="flex items-center gap-4 justify-between md:justify-end mt-2 md:mt-0">
                    <span>Kayıt: {order.date}</span>
                    <span className="flex items-center gap-1">Ödeme: <span className="font-bold text-gray-700 dark:text-gray-300">{order.paymentMethod}</span> {order.isPaid ? <span className="text-green-600 dark:text-green-400 font-bold">(Tahsil Edildi)</span> : <span className="text-red-500 dark:text-red-400 font-bold">(Bekliyor)</span>}</span>
                  </div>
                </div>

              </div>
            )}
          </div>
        ))}
        {filtered.length === 0 && <div className="text-center text-gray-500 dark:text-gray-400 py-10 rounded-lg border transition-colors bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">Kayıtlı iş emri bulunamadı.</div>}
      </div>
    </div>
  );
};

// --- DASHBOARD CONTAINER ---
const Dashboard = ({ user, onLogout }) => {
  const [activeTab, setActiveTab] = useState("orders");
  const [orders, setOrders] = useState([]);
  const [staff, setStaff] = useState([]);
  const [expenses, setExpenses] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

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
        customer: o.customerInfo || o.CustomerInfo || "Misafir",
        vehicle: o.vehicleInfo || o.VehicleInfo || "Araç Yok",
        plate: o.VehiclePlate || o.vehiclePlate || o.Plate || o.plate || "---",
        status: o.StatusTr || o.statusTr || o.Status || "Bekliyor",
        date: safeDate(o.Date || o.date || o.TransactionDate),
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

    } catch (error) {
      console.error("Veri çekme hatası:", error);
      setErrorMsg("Veriler yüklenirken hata oluştu.");
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Yardımcılar
  const handleDeleteOrder = async (id) => { if (confirm("Silinsin mi?")) { await orderService.delete(id); fetchData(); } };
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

  const stats = {
    totalOrders: orders.length,
    completedOrders: orders.filter(o => o.status === "Tamamlandı" || o.status === "Completed").length,
    pendingOrders: orders.filter(o => o.status !== "Tamamlandı" && o.status !== "Completed").length,
    totalRevenue: orders.filter(o => o.status === "Tamamlandı" || o.status === "Completed").reduce((sum, o) => sum + (o.totalPrice || 0), 0)
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
    const combinedItems = [...expenses.map(e => ({...e, source:'expense'})), ...orders.filter(o=>o.status==="Tamamlandı"||o.status==="Completed").map(o=>({id:o.id, date:o.date, title:`${o.plate} - ${o.customer}`, category:"İş Emri", amount:o.totalPrice, type:"income", source:'order'}))].sort((a,b)=>new Date(b.date)-new Date(a.date));
    return (
      <div>
        <div className="flex justify-between items-center mb-4"><h2 className="text-lg font-bold">Gelir / Gider</h2><button onClick={onAdd} className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2"><Plus size={18}/> Yeni Kayıt</button></div>
        <div className="overflow-x-auto"><table className="w-full text-left"><thead className="bg-gray-50 text-gray-500 text-sm border-b"><tr>{["No","Tarih","Açıklama","Kategori","Tutar",""].map(h=><th key={h} className="p-3">{h}</th>)}</tr></thead><tbody className="divide-y text-sm">{combinedItems.map((item,idx)=>(<tr key={`${item.source}-${item.id}-${idx}`} className="hover:bg-gray-50"><td className="p-3 font-mono text-gray-400">#{item.id}</td><td className="p-3 text-gray-600">{item.date}</td><td className="p-3 font-medium">{item.title}</td><td className="p-3"><span className={`px-2 py-1 rounded text-xs ${item.type==="income"?"bg-green-100 text-green-800":"bg-red-100 text-red-800"}`}>{item.category}</span></td><td className={`p-3 font-bold ${item.type==="income"?"text-green-600":"text-red-600"}`}>{item.type==="income"?"+":"-"}₺{item.amount?.toLocaleString()}</td><td className="p-3 text-right"><button onClick={()=>item.source==='order'?onDeleteOrder(item.id):onDelete(item.id)} className="text-red-400 hover:text-red-600"><Trash2 size={16}/></button></td></tr>))}</tbody></table></div>
      </div>
    );
  };

  return (
    <div 
      className="min-h-screen font-sans transition-colors duration-300
      bg-gray-100 text-gray-800
      dark:bg-dark-bg dark:text-gray-200"
    >
      <div className="shadow-sm border-b transition-colors
        bg-white border-gray-200
        dark:bg-dark-card dark:border-dark-border">
          <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
            <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-600 text-white dark:bg-brand dark:text-black">
                    <Car size={24}/>
                </div>
                <div>
                    <h1 className="text-xl font-bold text-gray-800 dark:text-gray-100">Bağlan Oto Care</h1>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Yönetim Paneli</p>
                </div>
            </div>
            
            <div className="flex items-center gap-4">
                <button onClick={toggleTheme} className="p-2 rounded-full transition-colors 
                    bg-gray-100 text-gray-600 hover:bg-gray-200
                    dark:bg-dark-hover dark:text-brand dark:hover:bg-dark-bg">
                    {isDark ? <Sun size={20}/> : <Moon size={20}/>}
                </button>
                <div className="h-6 w-px bg-gray-300 dark:bg-gray-600"></div>
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{user?.name}</span>
                <button onClick={onLogout} className="text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"><LogOut size={20}/></button>
            </div>
          </div>
      </div>
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
        <div className="rounded-t-lg flex gap-1 px-4 overflow-x-auto border-b bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">
          {[{id:"orders",label:"İş Emirleri",icon:ClipboardList},{id:"customers",label:"Müşteri Ekle",icon:Plus},{id:"staff",label:"Personel",icon:Users},{id:"accounting",label:"Muhasebe",icon:DollarSign},{id:"settings",label:"Ayarlar",icon:Settings}].map((tab)=>(
            <button key={tab.id} onClick={()=>tab.id==="customers"?setShowWizard(true):setActiveTab(tab.id)} 
            className={`flex items-center gap-2 px-4 py-3 border-b-2 whitespace-nowrap transition-colors 
            ${activeTab===tab.id 
                ? "border-blue-600 text-blue-600 dark:border-brand dark:text-brand" 
                : "border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200"}`}>
            <tab.icon size={18}/> {tab.label}</button>))}
        </div>
        <div className="rounded-b-lg shadow p-6 min-h-[400px] border border-t-0 bg-white border-gray-200 dark:bg-dark-card dark:border-dark-border">
          {errorMsg && <div className="bg-red-900/20 text-red-300 border border-red-900/50 p-3 rounded mb-4 flex items-center gap-2"><AlertTriangle size={18}/>{errorMsg}</div>}
          {loading ? <div className="flex justify-center items-center h-64"><Loader2 className="animate-spin text-brand" size={48}/></div> : (
            <>{activeTab==="orders"&&<OrderList orders={orders} onEdit={(o)=>setShowOrderDetail(o)} onDelete={handleDeleteOrder}/>}{activeTab==="staff"&&<StaffList staff={staff} onAdd={()=>setShowAddStaff(true)} onDetail={(p)=>setShowStaffDetail(p)} onDelete={handleDeleteStaff}/>}{activeTab==="accounting"&&<AccountingView expenses={expenses} orders={orders} onAdd={()=>setShowAddExpense(true)} onDelete={handleDeleteExpense} onDeleteOrder={handleDeleteOrder}/>}{activeTab==="settings"&&<SettingsView/>}</>
          )}
        </div>
      </div>
      {showWizard && <NewOrderWizard onClose={()=>setShowWizard(false)} onSuccess={()=>{fetchData();setShowWizard(false)}}/>}
      {showOrderDetail && <OrderDetailModal order={showOrderDetail} staff={staff} onClose={()=>setShowOrderDetail(null)} onSave={()=>{fetchData();setShowOrderDetail(null)}}/>}
      {showStaffDetail && <StaffDetailModal person={showStaffDetail} orders={orders} onClose={()=>setShowStaffDetail(null)}/>}{showAddStaff&&<AddStaffModal onClose={()=>setShowAddStaff(false)} onAdd={handleAddStaff}/>}{showAddExpense&&<AddTransactionModal onClose={()=>setShowAddExpense(false)} onAdd={handleAddExpense}/>}
    </div>
  );
};

export default Dashboard;
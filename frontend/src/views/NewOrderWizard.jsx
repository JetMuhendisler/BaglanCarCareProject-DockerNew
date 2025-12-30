import React, { useState, useEffect } from "react";
import { Check, ChevronRight, ChevronLeft, Car, Calendar, CreditCard, X, Loader2, User, Clock } from "lucide-react";
import { orderService, catalogService, personnelService } from "../api";
import CalendarView from "../components/CalendarView";

const NewOrderWizard = ({ onClose, onSuccess }) => {
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [dataLoading, setDataLoading] = useState(true);

  // --- CATALOG & STAFF DATA ---
  const [categories, setCategories] = useState([]);
  const [products, setProducts] = useState([]);
  const [staffList, setStaffList] = useState([]);
  const [existingOrders, setExistingOrders] = useState([]);

  // --- FORM STATE ---
  const [formData, setFormData] = useState({
    customerName: "", customerPhone: "", customerEmail: "",
    plateNumber: "", brand: "", model: "", color: "", year: "",
    selectedServices: [], 
    receivedDate: new Date().toISOString(), // Teslim Alınan (Sistem)
    targetDate: new Date().toISOString().split('T')[0], // Teslim Edilecek (Hedef)
    appointmentTime: "09:00",
    paymentMethod: "Nakit", isPaid: false,
    finalPrice: null,
    personnelIds: [] // Çoklu Personel seçimi için
  });

  // --- STEP 2 SELECTION STATES ---
  const [activeCategory, setActiveCategory] = useState(null);
  const [activeProduct, setActiveProduct] = useState(null);
  const [selectedVariant, setSelectedVariant] = useState(null);

  // VERİLERİ ÇEK
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [catsRes, prodsRes, staffRes, ordersRes] = await Promise.all([
            catalogService.getAllCategories(),
            catalogService.getAllProducts(),
            personnelService.getAll(),
            orderService.getAll()
        ]);
        setCategories(Array.isArray(catsRes) ? catsRes : catsRes.data || []);
        setProducts(Array.isArray(prodsRes) ? prodsRes : prodsRes.data || []);
        setStaffList(Array.isArray(staffRes) ? staffRes : staffRes.data || []);
        setExistingOrders(Array.isArray(ordersRes) ? ordersRes : ordersRes.data || []);
      } catch (err) {
        console.error("Veri yüklenemedi:", err);
      } finally {
        setDataLoading(false);
      }
    };
    fetchData();
  }, []);

  // --- HANDLERS ---
  const handleChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handlePersonnelToggle = (id) => {
      setFormData(prev => {
          const current = prev.personnelIds || [];
          if (current.includes(id)) {
              return { ...prev, personnelIds: current.filter(x => x !== id) };
          } else {
              return { ...prev, personnelIds: [...current, id] };
          }
      });
  };

  const handlePlateBlur = async () => {
    if (formData.plateNumber.length > 2) {
      try {
        const res = await orderService.search(formData.plateNumber);
        if (res && res.Found) {
          setFormData(prev => ({
            ...prev,
            customerName: res.CustomerName || res.customerName || "",
            customerPhone: res.Phone || res.phone || "",
            brand: res.Brand || res.brand || "",
            model: res.Model || res.model || ""
          }));
        }
      } catch (err) { console.log("Arama hatası", err); }
    }
  };

  // --- AKILLI HİZMET EKLEME MANTIĞI ---
  const addToCart = (categoryName, productName, variantName, partName, price) => {
    // Aynı hizmet var mı kontrolü
    const exists = formData.selectedServices.some(item => 
        item.category === categoryName &&
        item.product === productName &&
        item.spec === (variantName || "") &&
        item.part === (partName || "Standart")
    );

    if (exists) return;

    const newItem = {
      category: categoryName,
      product: productName,
      spec: variantName || "",
      part: partName || "Standart",
      price: price
    };
    
    setFormData(prev => ({
      ...prev,
      selectedServices: [...prev.selectedServices, newItem]
    }));
  };

  // 1. Ürün Seçimi
  const handleProductSelect = (prod) => {
    // Eğer ürünün mikron/varyantı YOKSA -> Direkt Ekle
    if (!prod.hasMicron) {
        addToCart(activeCategory.name, prod.name, "", "Tam Uygulama", prod.basePrice);
        // Seçimi sıfırla (başka ürün seçilebilsin)
        setActiveProduct(null); 
    } else {
        // Varyantı varsa -> Detay aç
        setActiveProduct(prod);
        setSelectedVariant(null);
    }
  };

  // 2. Varyant Seçimi
  const handleVariantSelect = (variant) => {
    // Eğer varyantın alt parçası YOKSA -> Direkt Ekle
    if (!variant.hasSubParts) {
        addToCart(
            activeCategory.name, 
            activeProduct.name, 
            variant.thicknessCode || variant.name, 
            "Tam Uygulama", 
            variant.variantPrice
        );
        setSelectedVariant(null);
    } else {
        // Alt parçası varsa -> Parçaları göster
        setSelectedVariant(variant);
    }
  };

  const removeServiceItem = (index) => {
    setFormData(prev => ({
      ...prev,
      selectedServices: prev.selectedServices.filter((_, i) => i !== index)
    }));
  };

  const handleSubmit = async () => {
    setLoading(true);
    try {
      const payload = {
        customerName: formData.customerName,
        customerPhone: formData.customerPhone,
        customerEmail: formData.customerEmail,
        plateNumber: formData.plateNumber,
        brand: formData.brand,
        model: formData.model,
        color: formData.color,
        year: formData.year,
        personnelIds: formData.personnelIds, // Çoklu seçim listesi
        receivedDate: formData.receivedDate,
        targetDate: new Date(`${formData.targetDate}T${formData.appointmentTime}`).toISOString(), // Hedef Tarih + Seçilen Saat
        totalPrice: formData.finalPrice !== null ? Number(formData.finalPrice) : formData.selectedServices.reduce((sum, item) => sum + item.price, 0),
        paymentMethod: formData.paymentMethod,
        isPaid: formData.isPaid,
        selectedServices: formData.selectedServices
      };

      await orderService.create(payload);
      onSuccess();
      onClose();
    } catch (error) {
      alert("Hata: " + (error.response?.data?.Message || error.message));
    } finally {
      setLoading(false);
    }
  };

  // ADIM 1: MÜŞTERİ & ARAÇ
  const renderStep1 = () => (
    <div className="space-y-4">
      <h3 className="font-bold text-lg flex items-center gap-2 text-gray-800 dark:text-gray-200"><Car size={20} className="text-blue-600 dark:text-brand"/> Müşteri ve Araç</h3>
      <div className="grid grid-cols-2 gap-4">
        <input className="border p-3 rounded-lg outline-none transition-colors
          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
          dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500" placeholder="Plaka (06ABC123)" 
          value={formData.plateNumber} 
          onChange={e => handleChange("plateNumber", e.target.value.toUpperCase())}
          onBlur={handlePlateBlur}
        />
        <input className="border p-3 rounded-lg outline-none transition-colors
          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
          dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500" placeholder="Telefon (5XX...)" 
          value={formData.customerPhone} onChange={e => handleChange("customerPhone", e.target.value)} />
        <input className="border p-3 rounded-lg outline-none transition-colors col-span-2
          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
          dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500" placeholder="Müşteri Adı Soyadı" 
          value={formData.customerName} onChange={e => handleChange("customerName", e.target.value)} />
        <input className="border p-3 rounded-lg outline-none transition-colors
          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
          dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500" placeholder="Marka (BMW)" 
          value={formData.brand} onChange={e => handleChange("brand", e.target.value)} />
        <input className="border p-3 rounded-lg outline-none transition-colors
          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
          dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500" placeholder="Model (320i)" 
          value={formData.model} onChange={e => handleChange("model", e.target.value)} />
        <input className="border p-3 rounded-lg outline-none transition-colors
          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
          dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500" placeholder="Renk" 
          value={formData.color} onChange={e => handleChange("color", e.target.value)} />
        <input className="border p-3 rounded-lg outline-none transition-colors
          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
          dark:bg-dark-bg dark:border-dark-border dark:text-white dark:focus:ring-brand dark:placeholder-gray-500" placeholder="Yıl" 
          value={formData.year} onChange={e => handleChange("year", e.target.value)} />
      </div>
    </div>
  );

  // ADIM 2: HİZMETLER (GÜNCELLENDİ)
  const renderStep2 = () => {
    if (dataLoading) return <div className="flex justify-center p-10"><Loader2 className="animate-spin"/> Yükleniyor...</div>;

    const filteredProducts = activeCategory 
        ? products.filter(p => p.categoryName === activeCategory.name || p.categoryId === activeCategory.id)
        : [];

    return (
      <div className="h-[500px] flex gap-4">
        {/* SOL: KATEGORİ LİSTESİ */}
        <div className="w-1/4 border-r pr-2 space-y-2 overflow-y-auto border-gray-200 dark:border-dark-border">
          {categories.map(cat => (
            <button key={cat.id} 
              onClick={() => { setActiveCategory(cat); setActiveProduct(null); setSelectedVariant(null); }}
              className={`w-full text-left p-3 rounded-lg font-medium transition-colors 
              ${activeCategory?.id === cat.id 
                  ? "bg-blue-600 text-white dark:bg-brand dark:text-white" 
                  : "text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-hover"}`}>
              {cat.name}
            </button>
          ))}
        </div>

        {/* ORTA: ÜRÜN VE VARYANT SEÇİMİ */}
        <div className="flex-1 overflow-y-auto pr-2">
          {activeCategory ? (
            <div>
              <h4 className="font-bold mb-3 text-gray-700 dark:text-brand">{activeCategory.name} Ürünleri</h4>
              
              {/* Ürün Listesi */}
               <div className="grid grid-cols-1 gap-3 mb-6">
                {filteredProducts.length > 0 ? filteredProducts.map((prod) => (
                  <div key={prod.id} 
                    className={`border p-3 rounded-lg cursor-pointer transition-all flex justify-between items-center 
                    ${activeProduct?.id === prod.id 
                        ? "border-blue-500 bg-blue-50 ring-1 ring-blue-500 dark:border-brand dark:bg-brand/10 dark:ring-brand" 
                        : "border-gray-200 hover:border-gray-400 dark:border-dark-border dark:hover:border-gray-500 dark:bg-dark-card"}`}
                    onClick={() => handleProductSelect(prod)}>
                    <div>
                        <div className={`font-semibold ${activeProduct?.id === prod.id ? "text-blue-900 dark:text-brand" : "text-gray-800 dark:text-gray-200"}`}>{prod.brand}</div>
                        <div className="text-sm text-gray-600 dark:text-gray-500">{prod.name}</div>
                    </div>
                    {/* Micron yoksa fiyatı göster */}
                    {!prod.hasMicron ? (
                        <span className="font-bold px-2 py-1 rounded text-xs border
                          bg-green-50 text-green-700 border-green-200
                          dark:text-brand dark:bg-brand/10 dark:border-brand/20">₺{prod.basePrice}</span>
                    ) : (
                        <ChevronRight size={16} className="text-gray-400 dark:text-gray-500"/>
                    )}
                  </div>
                )) : <div className="text-gray-500 italic">Bu kategoride ürün bulunamadı.</div>}
              </div>

              {/* VARYANTLAR (Sadece Ürün Seçiliyse ve Micron Varsa) */}
              {activeProduct && activeProduct.hasMicron && activeProduct.variants && activeProduct.variants.length > 0 && (
                <div className="mb-6 animate-fade-in p-3 rounded border transition-colors
                  bg-white border-gray-300
                  dark:bg-dark-bg/50 dark:border-dark-border">
                  <label className="text-xs font-bold text-gray-500 uppercase block mb-2">Tip / Kalınlık Seçimi:</label>
                  <div className="flex flex-wrap gap-2">
                    {activeProduct.variants.map((v, idx) => {
                      const uniqueKey = v.thicknessCode || v.name || idx; 
                      return (
                        <button 
                          key={uniqueKey} 
                          onClick={() => handleVariantSelect(v)}
                          className={`px-4 py-2 border rounded-md transition-colors font-medium text-sm flex flex-col items-center
                            ${selectedVariant?.thicknessCode === v.thicknessCode && selectedVariant?.name === v.name
                              ? "bg-purple-100 text-purple-900 border-purple-500 shadow-md transform scale-105 dark:bg-purple-900/50 dark:text-purple-200" 
                              : "bg-white text-gray-800 border-gray-300 hover:bg-gray-100 dark:bg-dark-card dark:text-gray-300 dark:border-dark-border dark:hover:border-gray-500 dark:hover:bg-dark-hover"}`}>
                          
                          <span>{v.thicknessCode || v.name}</span>
                          {/* Alt parça yoksa fiyatı göster */}
                          {!v.hasSubParts && <span className="text-xs font-bold mt-1 opacity-90">₺{v.variantPrice}</span>}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* PARÇA FİYATLARI (Sadece Varyant Seçiliyse ve Alt Parça Varsa) */}
              {selectedVariant && selectedVariant.hasSubParts && selectedVariant.partPrices && (
                <div className="animate-fade-in">
                  <label className="text-xs font-bold text-gray-500 uppercase block mb-2">
                    Uygulanacak Parça ({selectedVariant.thicknessCode || selectedVariant.name}):
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    {selectedVariant.partPrices.map((part, pIdx) => {
                      // Parça daha önce seçildi mi kontrolü
                      const isSelected = formData.selectedServices.some(item => 
                          item.category === activeCategory.name &&
                          item.product === activeProduct.name &&
                          item.spec === (selectedVariant.thicknessCode || selectedVariant.name) && 
                          item.part === part.partName
                      );

                      return (
                        <button key={pIdx} 
                          disabled={isSelected}
                          onClick={() => addToCart(
                              activeCategory.name, 
                              activeProduct.name, 
                              selectedVariant.thicknessCode || selectedVariant.name, 
                              part.partName, 
                              part.price
                          )}
                          className={`flex justify-between items-center p-3 border rounded-lg transition-colors group
                            ${isSelected 
                                ? "bg-gray-100 border-gray-200 text-gray-400 cursor-not-allowed dark:bg-dark-bg dark:border-dark-border dark:text-gray-600" 
                                : "cursor-pointer bg-white border-gray-200 hover:bg-gray-50 hover:border-gray-300 dark:bg-dark-card dark:border-dark-border dark:hover:bg-brand/10 dark:hover:border-brand/50"}`}>
                          <span className={`font-medium ${isSelected ? "" : "text-gray-800 group-hover:text-blue-600 dark:text-gray-300 dark:group-hover:text-brand"}`}>
                              {part.partName} {isSelected && <Check size={14} className="inline ml-1"/>}
                          </span>
                          <span className={`font-bold ${isSelected ? "" : "text-brand"}`}>
                              +₺{part.price}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          ) : <div className="text-gray-400 text-center mt-20 flex flex-col items-center"><ChevronLeft className="mb-2"/> Lütfen soldan bir kategori seçin</div>}
        </div>

        {/* SAĞ: SEÇİLENLER ÖZETİ */}
        <div className="w-1/4 border-l pl-2 flex flex-col rounded-r-lg transition-colors
          border-gray-200 bg-gray-50
          dark:border-dark-border dark:bg-dark-bg/30">
          <h4 className="font-bold mb-2 p-2 border-b text-gray-800 border-gray-200 dark:border-dark-border dark:text-gray-200">Seçilen Hizmetler</h4>
          <div className="flex-1 overflow-y-auto space-y-2 p-2">
            {formData.selectedServices.map((item, i) => (
              <div key={i} className="p-3 rounded shadow-sm border text-sm relative group animate-fade-in transition-colors
                bg-white border-gray-200
                dark:bg-dark-card dark:border-dark-border">
                <button onClick={() => removeServiceItem(i)} className="absolute top-1 right-1 text-gray-400 hover:text-red-500 transition-colors"><X size={14}/></button>
                <div className="font-semibold text-blue-700 dark:text-brand-light">{item.category}</div>
                <div className="text-gray-600 dark:text-gray-400">{item.product}</div>
                {item.spec && <div className="text-xs font-medium inline-block px-1 rounded mt-1 border
                  bg-purple-100 text-purple-700 border-purple-200
                  dark:text-purple-300 dark:bg-purple-900/30 dark:border-purple-800">{item.spec}</div>}
                <div className="flex justify-between mt-2 pt-2 border-t border-dashed border-gray-200 dark:border-gray-700">
                  <span className="text-gray-600 dark:text-gray-300">{item.part}</span>
                  <span className="font-bold text-gray-800 dark:text-gray-100">₺{item.price}</span>
                </div>
              </div>
            ))}
            {formData.selectedServices.length === 0 && <div className="text-gray-400 text-center text-sm mt-10">Henüz hizmet eklenmedi.</div>}
          </div>
          <div className="border-t p-3 mt-2 rounded-lg shadow-sm transition-colors
            bg-white border-gray-200
            dark:bg-dark-card dark:border-dark-border">
              <div className="flex justify-between text-lg font-bold text-gray-800 dark:text-gray-200">
                <span>Toplam:</span>
                <span>₺{formData.selectedServices.reduce((a,b)=>a+b.price, 0)}</span>
              </div>
          </div>
        </div>
      </div>
    );
  };

  const generateTimeSlots = () => {
    const slots = [];
    for (let i = 8; i <= 19; i++) {
        slots.push(`${i < 10 ? '0'+i : i}:00`);
        slots.push(`${i < 10 ? '0'+i : i}:30`);
    }
    return slots;
  };

  const calculateTotal = () => formData.selectedServices.reduce((sum, item) => sum + item.price, 0);

  // ADIM 3: TAKVİM & PLANLAMA (Split View)
  const renderStep3 = () => {
    // Helper to get orders for selected date
    const selectedOrders = existingOrders.filter(o => {
        const oDate = new Date(o.rawDate || o.date || o.Date || o.TransactionDate);
        return !isNaN(oDate.getTime()) && oDate.toISOString().split('T')[0] === formData.targetDate;
    });

    return (
      <div className="h-full flex flex-col md:flex-row gap-6">
         {/* LEFT: CALENDAR (Flexible) */}
         <div className="flex-1 flex flex-col min-w-0">
             <div className="flex justify-between items-center mb-3">
                 <h3 className="font-bold text-lg flex items-center gap-2 text-gray-800 dark:text-gray-200"><Calendar className="text-blue-600 dark:text-brand"/> Tarih Planlama</h3>
                 <div className="text-xs bg-gray-100 dark:bg-dark-card px-2 py-1 rounded border border-gray-200 dark:border-dark-border flex items-center gap-1">
                     <span className="text-gray-500">Teslim Alınan:</span>
                     <span className="font-mono font-bold">{new Date(formData.receivedDate).toLocaleTimeString('tr-TR', {hour:'2-digit', minute:'2-digit'})}</span>
                 </div>
             </div>
             
             <div className="flex-1 overflow-y-auto pr-1">
                 <CalendarView 
                    orders={existingOrders} 
                    selectedDate={formData.targetDate}
                    onDateSelect={(d) => handleChange("targetDate", d)}
                    showDetails={false} // Hide built-in details, we show them on right
                 />
             </div>
         </div>

         {/* RIGHT: DETAILS & TIME (Fixed Width) */}
         <div className="w-full md:w-80 flex flex-col gap-4 border-l border-gray-100 dark:border-dark-border pl-6">
            
            {/* 1. SEÇİLİ TARİH & SAAT */}
            <div className="bg-blue-50 dark:bg-brand/10 p-4 rounded-xl border border-blue-100 dark:border-brand/20">
                <label className="block text-xs font-bold text-blue-800 dark:text-brand-light mb-1 uppercase tracking-wider">Hedef Teslim Zamanı</label>
                <div className="text-xl font-bold text-gray-800 dark:text-gray-100 mb-3">
                    {new Date(formData.targetDate).toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', weekday: 'long' })}
                </div>

                <div className="relative">
                    <Clock className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18}/>
                    <select 
                        value={formData.appointmentTime}
                        onChange={(e) => handleChange("appointmentTime", e.target.value)}
                        className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-200 dark:border-dark-border bg-white dark:bg-dark-bg text-gray-800 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 outline-none appearance-none"
                    >
                        {generateTimeSlots().map(t => (
                            <option key={t} value={t}>{t}</option>
                        ))}
                    </select>
                </div>
            </div>

            {/* 2. GÜNLÜK İŞ PLAN (Compact List) */}
            <div className="flex-1 flex flex-col min-h-0 bg-gray-50 dark:bg-dark-card rounded-xl border border-gray-200 dark:border-dark-border p-4">
                <h4 className="text-sm font-bold text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-orange-500"></div>
                    Günlük İş Planı ({selectedOrders.length})
                </h4>
                
                <div className="flex-1 overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                    {selectedOrders.length === 0 ? (
                        <div className="text-center py-8 text-gray-400 text-sm italic">
                           Bu tarihte kayıtlı işlem yok.<br/>Müsait.
                        </div>
                    ) : (
                        selectedOrders.map((o, i) => (
                            <div key={i} className="bg-white dark:bg-dark-bg p-2 rounded shadow-sm border border-gray-100 dark:border-dark-border/50 text-sm">
                                <div className="flex justify-between items-start mb-1">
                                    <span className="font-bold text-gray-800 dark:text-gray-200">{o.plate}</span>
                                    <span className={`text-[10px] px-1.5 rounded-full 
                                        ${(o.status||"").includes("Bekliyor") ? "bg-orange-100 text-orange-700" : 
                                          (o.status||"").includes("Tamam") ? "bg-green-100 text-green-700" : 
                                          "bg-blue-100 text-blue-700"}`}>{o.status}</span>
                                </div>
                                <div className="text-xs text-gray-500 truncate">{o.brand} {o.model}</div>
                            </div>
                        ))
                    )}
                </div>
            </div>
         </div>
      </div>
    );
  };

  // ADIM 4: DETAYLAR (Eski Step 3)
  const renderStep4 = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-6">
        
        {/* SOL: PERSONEL SEÇİMİ */}
        <div className="space-y-4">
          {/* Personel Seçimi */}
          <div className="rounded-lg p-4 shadow-sm border transition-colors
            bg-white border-gray-200
            dark:bg-dark-card dark:border-dark-border">
              <h3 className="font-bold text-lg mb-3 flex items-center gap-2 text-gray-800 dark:text-gray-200"><User className="text-blue-600 dark:text-brand"/> Personel Ata (Çoklu Seçim)</h3>
              <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
                 {staffList.map(p => {
                   const isSelected = (formData.personnelIds || []).includes(p.id);
                   return (
                   <div key={p.id} 
                      onClick={() => handlePersonnelToggle(p.id)}
                      className={`p-3 rounded-lg border cursor-pointer flex items-center gap-3 transition-all
                      ${isSelected 
                          ? "bg-blue-50 border-blue-500 ring-1 ring-blue-500 dark:bg-brand/20 dark:border-brand dark:ring-brand" 
                          : "hover:bg-gray-50 border-gray-200 dark:border-dark-border dark:hover:bg-dark-hover"}`}>
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-white shadow-sm flex-shrink-0
                          ${isSelected ? "bg-blue-600 dark:bg-brand" : "bg-gray-400"}`}>
                          {p.firstName?.charAt(0) || "?"}
                        </div>
                        <div className="flex flex-col min-w-0">
                           <span className={`font-bold truncate ${isSelected ? "text-blue-900 dark:text-white" : "text-gray-700 dark:text-gray-300"}`}>
                             {p.firstName} {p.lastName}
                           </span>
                           <span className="text-xs text-gray-500 dark:text-gray-400 truncate">{p.position || p.role || "Pozisyon Yok"}</span>
                        </div>
                        {isSelected && <Check className="ml-auto text-blue-600 dark:text-brand" size={16}/>}
                   </div>
                   );
                 })}
                 {staffList.length === 0 && <div className="col-span-2 text-center text-gray-400 py-4">Kayıtlı personel yok.</div>}
              </div>
          </div>
        </div>
        {/* SAĞ: ÖDEME */}
        <div>
          <h3 className="font-bold text-lg mb-3 flex items-center gap-2 text-gray-800 dark:text-gray-200"><CreditCard className="text-blue-600 dark:text-brand"/> Ödeme</h3>
          
          <div className="p-4 rounded-lg mb-4 border shadow-sm transition-colors
            bg-blue-50 border-blue-100
            dark:bg-brand/10 dark:border-brand/20">
              <div className="flex justify-between items-center mb-2">
                  <span className="text-gray-600 dark:text-gray-400">Liste Fiyatı:</span>
                  <span className="font-bold text-lg text-gray-500 line-through">₺{calculateTotal()}</span>
              </div>
              <div className="flex justify-between items-center p-3 rounded border ring-1 transition-colors
                bg-white border-gray-300 ring-blue-200
                dark:bg-dark-card dark:border-dark-border dark:ring-brand/50">
                  <span className="text-blue-700 font-bold dark:text-brand">Nihai Tutar:</span>
                  <input type="number" 
                      className="w-32 text-right font-bold bg-transparent outline-none text-xl text-blue-700 dark:text-brand"
                      placeholder={calculateTotal()}
                      value={formData.finalPrice !== null ? formData.finalPrice : calculateTotal()}
                      onChange={e => handleChange("finalPrice", e.target.value)}
                  />
              </div>
          </div>

          <div className="space-y-3">
            <h4 className="font-medium text-gray-700 dark:text-gray-400">Ödeme Yöntemi</h4>
            <div className="grid grid-cols-3 gap-3">
                {["Nakit", "Kredi Kartı", "Havale"].map(m => (
                <label key={m} className={`flex flex-col items-center justify-center p-3 border rounded-lg cursor-pointer transition-all 
                  ${formData.paymentMethod === m 
                      ? "bg-blue-50 border-blue-500 text-blue-700 shadow-sm dark:bg-brand/10 dark:border-brand dark:text-brand" 
                      : "bg-white border-gray-200 text-gray-700 hover:bg-gray-50 dark:bg-dark-card dark:border-dark-border dark:text-gray-300 dark:hover:bg-dark-hover"}`}>
                    <input type="radio" name="payment" className="hidden" checked={formData.paymentMethod === m} onChange={() => handleChange("paymentMethod", m)} />
                    <span className="font-medium">{m}</span>
                </label>
                ))}
            </div>
            
            <label className="flex items-center gap-3 mt-4 p-4 border rounded-lg cursor-pointer shadow-sm transition-colors
              bg-white border-gray-200 hover:bg-gray-50
              dark:bg-dark-card dark:border-dark-border dark:hover:bg-dark-hover">
              <input type="checkbox" className="w-5 h-5 text-blue-600 dark:text-brand rounded focus:ring-offset-0" checked={formData.isPaid} onChange={e => handleChange("isPaid", e.target.checked)} />
              <span className="font-medium text-gray-800 dark:text-gray-200">Ödeme Tahsil Edildi</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
      <div className="w-full max-w-5xl rounded-2xl shadow-2xl h-[90vh] flex flex-col overflow-hidden border
        bg-white border-gray-200
        dark:bg-dark-bg dark:border-dark-border">
        {/* HEADER */}
        <div className="p-5 border-b flex justify-between items-center
          bg-gray-50 border-gray-200
          dark:bg-dark-card dark:border-dark-border">
          <h2 className="text-2xl font-bold text-gray-800 dark:text-gray-100">Yeni İş Emri Oluştur</h2>
          <button onClick={onClose} className="p-2 rounded-full transition-colors hover:bg-red-50 text-gray-500 hover:text-red-500 dark:hover:bg-red-400/20 dark:text-gray-400 dark:hover:text-red-400"><X /></button>
        </div>

        {/* STEPPER */}
        <div className="flex justify-center py-4 shadow-sm z-10 border-b
          bg-white border-gray-200
          dark:bg-dark-card dark:border-dark-border">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className={`flex items-center ${i < 4 ? "after:content-[''] after:w-16 after:h-1 after:mx-2 after:rounded after:bg-gray-200 dark:after:bg-dark-border" : ""}`}>
              <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold transition-all shadow-md 
                ${step === i 
                    ? "bg-blue-600 text-white scale-110 dark:bg-brand" 
                    : step > i 
                        ? "bg-green-500 text-white dark:bg-green-600" 
                        : "bg-gray-200 text-gray-500 dark:bg-dark-hover dark:text-gray-500"}`}>
                {step > i ? <Check size={20}/> : i}
              </div>
            </div>
          ))}
        </div>

        {/* CONTENT */}
        <div className="flex-1 p-6 overflow-y-auto bg-white dark:bg-dark-bg/50">
          {step === 1 && renderStep1()}
          {step === 2 && renderStep2()}
          {step === 3 && renderStep3()}
          {step === 4 && renderStep4()}
        </div>

        {/* FOOTER */}
        <div className="p-5 border-t flex justify-between
          bg-white border-gray-200
          dark:bg-dark-card dark:border-dark-border">
          <button onClick={() => step > 1 ? setStep(step - 1) : onClose()} className="px-6 py-3 border rounded-lg flex items-center gap-2 font-medium transition-colors
            border-gray-300 text-gray-700 hover:bg-gray-100
            dark:border-dark-border dark:text-gray-300 dark:hover:bg-dark-hover">
            <ChevronLeft size={18}/> Geri
          </button>
          
          {step < 4 ? (
            <button onClick={() => setStep(step + 1)} disabled={step === 1 && !formData.plateNumber} 
              className="px-8 py-3 rounded-lg flex items-center gap-2 font-bold shadow-lg disabled:opacity-50 disabled:shadow-none transition-all
              bg-blue-600 text-white hover:bg-blue-700 shadow-blue-200
              dark:bg-brand dark:text-white dark:hover:bg-brand-dark dark:shadow-brand/20">
              İleri <ChevronRight size={18}/>
            </button>
          ) : (
            <button onClick={handleSubmit} disabled={loading}
              className="px-10 py-3 rounded-lg font-bold shadow-lg flex items-center gap-2 transition-all
              bg-green-600 text-white hover:bg-green-700 shadow-green-200
              dark:bg-green-600 dark:hover:bg-green-700 dark:shadow-green-900/50">
              {loading ? <Loader2 className="animate-spin"/> : <Check size={20}/>} {loading ? "Kaydediliyor..." : "Siparişi Tamamla"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default NewOrderWizard;
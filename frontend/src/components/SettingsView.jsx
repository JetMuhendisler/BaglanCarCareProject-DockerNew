import React, { useState, useEffect } from "react";
import { 
  Plus, Trash2, Edit2, Save, X, Check, Layers, Box, 
  ChevronDown, ChevronRight, Tag, Loader2, ShieldCheck, DollarSign, ListTree 
} from "lucide-react";
import { catalogService } from "../api";

// --- INLINE PRICE EDITABLE COMPONENT ---
const PriceEditable = ({ value, onSave, className }) => {
  const [isEditing, setIsEditing] = useState(false);
  const [currentValue, setCurrentValue] = useState(value);

  const handleSave = async () => {
    if (parseFloat(currentValue) !== parseFloat(value)) {
      await onSave(currentValue);
    }
    setIsEditing(false);
  };

  const handleCancel = () => {
    setCurrentValue(value);
    setIsEditing(false);
  };

  if (isEditing) {
    return (
      <div className="flex items-center gap-1 animate-in fade-in zoom-in duration-200" onClick={(e) => e.stopPropagation()}>
        <input 
          type="number" 
          className="w-20 border rounded px-1 py-0.5 text-sm outline-none transition-colors
            border-blue-200 bg-white text-gray-900 focus:ring-blue-500
            dark:border-brand/50 dark:bg-dark-bg dark:text-white dark:focus:ring-brand" 
          value={currentValue}  
          autoFocus
          onChange={(e) => setCurrentValue(e.target.value)}
          onKeyDown={(e) => { if(e.key === 'Enter') handleSave(); if(e.key === 'Escape') handleCancel(); }}
        />
        <button onClick={handleSave} className="text-green-600 hover:bg-green-100 dark:text-brand dark:hover:bg-brand/10 p-0.5 rounded"><Check size={16}/></button>
        <button onClick={handleCancel} className="text-red-500 hover:bg-red-100 dark:text-red-400 dark:hover:bg-red-400/10 p-0.5 rounded"><X size={16}/></button>
      </div>
    );
  }

  return (
    <span 
      onClick={(e) => { e.stopPropagation(); setIsEditing(true); }} 
      className={`cursor-pointer hover:underline decoration-dashed underline-offset-4 decoration-brand/50 hover:text-brand transition-colors ${className}`}  
      title="Düzenlemek için tıklayın"
    >
      ₺{parseFloat(value).toLocaleString()}
    </span>
  );
};

const SettingsView = () => {
  const [activeTab, setActiveTab] = useState("products");
  const [categories, setCategories] = useState([]);
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [expandedProductId, setExpandedProductId] = useState(null);

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalType, setModalType] = useState(null); // 'CATEGORY', 'PRODUCT', 'VARIANT', 'PRICE'
  const [editingItem, setEditingItem] = useState(null);
  
  // İşlem yapılan Parent ID'ler
  const [parentId, setParentId] = useState(null); 

  const [formData, setFormData] = useState({});

  // Veri Çekme
  const fetchData = async () => {
    setLoading(true);
    try {
      const [catsRes, prodsRes] = await Promise.all([
        catalogService.getAllCategories(),
        catalogService.getAllProducts()
      ]);
      setCategories(Array.isArray(catsRes) ? catsRes : catsRes.data || []);
      setProducts(Array.isArray(prodsRes) ? prodsRes : prodsRes.data || []);
    } catch (error) {
      console.error("Veri hatası:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  // Modal Açma
  const openModal = (type, item = null, pId = null) => {
    setModalType(type);
    setEditingItem(item);
    setParentId(pId);
    setFormData({}); // Formu temizle

    // --- FORM VARSAYILANLARI ---
    if (item) {
        // Düzenleme Modu (Mevcut verileri doldur)
        // Not: Burada detaylı maplemeler gerekebilir, şimdilik basit tutuyoruz.
    } else {
        // Yeni Ekleme Modu
        if (type === 'PRODUCT') {
            setFormData({ 
                categoryId: "", name: "", brand: "", description: "", 
                hasMicron: false, basePrice: 0 
            });
        }
        if (type === 'VARIANT') {
            setFormData({ 
                name: "", thicknessCode: "", 
                hasSubParts: false, variantPrice: 0 
            });
        }
        if (type === 'PRICE') {
            setFormData({ partName: "", price: 0, isExtra: false });
        }
        if (type === 'CATEGORY') {
            setFormData({ name: "", description: "" });
        }
    }
    setIsModalOpen(true);
  };

  const closeModal = () => { setIsModalOpen(false); setFormData({}); setEditingItem(null); setParentId(null); };

  // --- KAYDETME MANTIĞI ---
  const handleSave = async (e) => {
    e.preventDefault();
    try {
      // 1. KATEGORİ
      if (modalType === 'CATEGORY') {
        if (editingItem) await catalogService.updateCategory({ ...formData, id: editingItem.id });
        else await catalogService.createCategory(formData);
      } 
      
      // 2. ÜRÜN (LEVEL 1)
      else if (modalType === 'PRODUCT') {
        // hasMicron true ise, basePrice 0 gönderilir
        const payload = {
            ...formData,
            categoryId: parseInt(formData.categoryId),
            basePrice: formData.hasMicron ? 0 : parseFloat(formData.basePrice)
        };

        if (editingItem) await catalogService.updateProduct({ ...payload, id: editingItem.id });
        else await catalogService.createProduct(payload);
      }
      
      // 3. VARYANT (LEVEL 2)
      else if (modalType === 'VARIANT') {
        // hasSubParts true ise, variantPrice 0 gönderilir
        const payload = {
            ...formData,
            productId: parentId, // Parent ID buradan gelir
            variantPrice: formData.hasSubParts ? 0 : parseFloat(formData.variantPrice)
        };

        if (editingItem) await catalogService.updateVariant({ ...payload, id: editingItem.id });
        else await catalogService.createVariant(payload);
      }

      // 4. PARÇA FİYAT (LEVEL 3)
      else if (modalType === 'PRICE') {
        const payload = {
            ...formData,
            variantId: parentId, // Parent ID (Varyant ID) buradan gelir
            price: parseFloat(formData.price)
        };
        // Backend'de createPartPrice endpointi VariantId bekliyor, isimlendirme uydu.
        if (editingItem) await catalogService.updatePartPrice({ ...payload, id: editingItem.id });
        else await catalogService.createPartPrice(payload);
      }

      alert("İşlem Başarılı!");
      closeModal();
      fetchData(); 
    } catch (error) {
      alert("Hata: " + (error.response?.data?.Message || error.message));
    }
  };

  // --- INLINE UPDATE HANDLERS ---
  const handleInlineUpdateVariant = async (variant, productId, newPrice) => {
    try {
        const payload = {
            id: variant.id,
            productId: productId,
            name: variant.name,
            thicknessCode: variant.thicknessCode,
            hasSubParts: false, 
            variantPrice: parseFloat(newPrice)
        };
        await catalogService.updateVariant(payload);
        fetchData();
    } catch (error) {
        alert("Güncelleme başarısız: " + error.message);
    }
  };

  const handleInlineUpdatePartPrice = async (priceItem, variantId, newPrice) => {
    try {
        const payload = {
            id: priceItem.id,
            variantId: variantId,
            partName: priceItem.partName,
            isExtra: priceItem.isExtra,
            price: parseFloat(newPrice)
        };
        await catalogService.updatePartPrice(payload);
        fetchData();
    } catch (error) {
        alert("Güncelleme başarısız: " + error.message);
    }
  };

  const handleDelete = async (type, id) => {
    if (!confirm("Silmek istediğinize emin misiniz?")) return;
    try {
      if (type === 'CATEGORY') await catalogService.deleteCategory(id);
      if (type === 'PRODUCT') await catalogService.deleteProduct(id);
      if (type === 'VARIANT') await catalogService.deleteVariant(id);
      if (type === 'PRICE') await catalogService.deletePartPrice(id);
      fetchData();
    } catch (error) {
      alert("Silinemedi: " + error.message);
    }
  };

  return (
    <div className="p-6 pb-24 space-y-6 min-h-screen
      bg-gray-100 
      dark:bg-dark-bg text-gray-800 dark:text-gray-200">
      {/* BAŞLIK */}
      <div className="flex flex-col md:flex-row justify-between items-center gap-4 p-4 rounded-xl shadow-sm border transition-colors
        bg-white border-gray-200
        dark:bg-dark-card dark:border-dark-border">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2 text-gray-800 dark:text-gray-100">
            <ShieldCheck className="text-blue-600 dark:text-brand"/> Katalog Yönetimi
          </h2>
          <p className="text-gray-500 dark:text-gray-400 text-sm">Ürünleri, mikronları ve parça fiyatlarını yapılandırın.</p>
        </div>
        <div className="flex p-1 rounded-lg border transition-colors
          bg-gray-100 border-gray-200
          dark:bg-dark-bg dark:border-dark-border">
          <button onClick={() => setActiveTab("categories")} className={`px-4 py-2 rounded-md font-medium transition-all flex items-center gap-2 
            ${activeTab === "categories" 
                ? "bg-white text-blue-600 shadow dark:bg-dark-card dark:text-brand" 
                : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"}`}><Layers size={18}/> Kategoriler</button>
          <button onClick={() => setActiveTab("products")} className={`px-4 py-2 rounded-md font-medium transition-all flex items-center gap-2 
            ${activeTab === "products" 
                ? "bg-white text-blue-600 shadow dark:bg-dark-card dark:text-brand" 
                : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"}`}><Box size={18}/> Ürünler</button>
        </div>
      </div>

      {loading && <div className="flex justify-center p-10"><Loader2 className="animate-spin text-blue-600 dark:text-brand w-8 h-8"/></div>}

      {/* KATEGORİ LİSTESİ */}
      {!loading && activeTab === "categories" && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button onClick={() => openModal('CATEGORY')} className="flex flex-col items-center justify-center p-6 border-2 border-dashed rounded-xl h-32 transition-all
             border-gray-300 text-gray-400 hover:border-blue-500 hover:text-blue-500 bg-white
             dark:bg-dark-card dark:border-dark-border dark:text-gray-500 dark:hover:border-brand dark:hover:text-brand">
            <Plus size={32} /> <span className="font-bold mt-2">Yeni Kategori</span>
          </button>
          {categories.map(cat => (
            <div key={cat.id} className="p-5 rounded-xl shadow-sm border flex justify-between items-center group transition-all
              bg-white border-gray-200 hover:border-blue-400
              dark:bg-dark-card dark:border-dark-border dark:hover:border-brand/50">
              <div><h3 className="font-bold text-lg text-gray-800 dark:text-gray-200">{cat.name}</h3><p className="text-gray-500 text-sm">{cat.description}</p></div>
              <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                <button onClick={() => openModal('CATEGORY', cat)} className="p-2 rounded text-gray-400 hover:text-blue-600 hover:bg-blue-50 dark:hover:text-brand dark:hover:bg-dark-hover"><Edit2 size={16}/></button>
                <button onClick={() => handleDelete('CATEGORY', cat.id)} className="p-2 rounded text-gray-400 hover:text-red-500 hover:bg-red-50 dark:hover:text-red-400 dark:hover:bg-dark-hover"><Trash2 size={16}/></button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ÜRÜN LİSTESİ (HİYERARŞİK GÖRÜNÜM) */}
      {!loading && activeTab === "products" && (
        <div className="space-y-4">
          <div className="flex justify-end">
             <button onClick={() => openModal('PRODUCT')} className="px-4 py-2 rounded-lg font-bold flex items-center gap-2 shadow-md transition-all
               bg-blue-600 text-white hover:bg-blue-700
               dark:bg-brand dark:text-white dark:hover:bg-brand-dark"><Plus size={20}/> Yeni Ürün Ekle</button>
          </div>
          {products.map(prod => (
            <div key={prod.id} className="rounded-xl shadow-sm border overflow-hidden transition-colors
              bg-white border-gray-200
              dark:bg-dark-card dark:border-dark-border">
              
              {/* 1. SEVİYE: ÜRÜN BAŞLIĞI */}
              <div className="p-4 flex items-center justify-between cursor-pointer transition-colors border-b
                hover:bg-gray-50 border-gray-100
                dark:hover:bg-dark-hover dark:border-dark-border" onClick={() => setExpandedProductId(expandedProductId === prod.id ? null : prod.id)}>
                <div className="flex items-center gap-4">
                  <div className={`p-2 rounded-full transition-colors ${expandedProductId === prod.id 
                    ? "bg-blue-600 text-white dark:bg-brand" 
                    : "bg-gray-100 text-gray-500 dark:bg-dark-bg"}`}>
                    {expandedProductId === prod.id ? <ChevronDown size={20}/> : <ChevronRight size={20}/>}
                  </div>
                  <div>
                    <h3 className="font-bold text-lg flex items-center gap-2 text-gray-800 dark:text-gray-200">{prod.brand} <span className="font-normal text-gray-500 dark:text-gray-400">{prod.name}</span></h3>
                    <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs font-bold uppercase px-2 py-0.5 rounded border
                          bg-gray-100 text-gray-600 border-gray-200
                          dark:bg-dark-bg dark:text-gray-500 dark:border-dark-border">{prod.categoryName}</span>
                        {/* Micron Var mı Badge */}
                        {prod.hasMicron ? 
                            <span className="text-xs px-2 py-0.5 rounded border font-medium
                              bg-purple-100 text-purple-700 border-purple-200
                              dark:bg-purple-900/30 dark:text-purple-300 dark:border-purple-800">Micronlu</span> : 
                            <span className="text-xs px-2 py-0.5 rounded border font-bold
                              bg-green-100 text-green-700 border-green-200
                              dark:bg-green-900/30 dark:text-green-400 dark:border-green-800">Tek Fiyat: ₺{prod.basePrice}</span>
                        }
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                    <button onClick={(e) => { e.stopPropagation(); handleDelete('PRODUCT', prod.id); }} className="p-2 text-gray-400 hover:text-red-500 hover:bg-gray-100 dark:hover:bg-dark-bg rounded transition-colors"><Trash2 size={18}/></button>
                </div>
              </div>

              {/* 2. SEVİYE: VARYANTLAR (ACCORDION) */}
              {expandedProductId === prod.id && (
                <div className="p-6 bg-gray-50 dark:bg-dark-bg/30">
                  <div className="flex justify-between items-center mb-4">
                      <h4 className="font-bold text-gray-500 dark:text-gray-400 flex items-center gap-2 text-sm uppercase tracking-wide"><ListTree size={16}/> Varyantlar / Seçenekler</h4>
                      <button onClick={() => openModal('VARIANT', null, prod.id)} className="text-xs px-3 py-1.5 rounded-md font-bold flex items-center gap-1 shadow-sm transition-colors
                        bg-white border border-blue-200 text-blue-600 hover:bg-blue-50
                        dark:bg-dark-card dark:border-brand dark:text-brand dark:hover:bg-dark-hover"><Plus size={14}/> Varyant Ekle</button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {prod.variants?.map((variant, vIdx) => {
                      const variantId = variant.id;
                      return (
                      <div key={vIdx} className="rounded-lg p-4 shadow-sm relative group transition-colors border
                        bg-white border-gray-200 hover:border-blue-300
                        dark:bg-dark-card dark:border-dark-border dark:hover:border-brand/50">
                        <div className="flex justify-between items-start border-b pb-2 mb-3
                          border-gray-100 dark:border-dark-border">
                           <div>
                               <span className="block font-bold text-lg text-gray-800 dark:text-brand-dark">{variant.thicknessCode || "Kodsuz"}</span>
                               <span className="text-xs text-gray-500 dark:text-gray-400">{variant.name}</span>
                           </div>
                           <div className="flex items-center gap-2">
                               {/* Eğer Alt Parça VARSA -> Fiyat Ekle Butonu Göster */}
                               {variant.hasSubParts ? (
                                   <button onClick={() => openModal('PRICE', null, variantId)} className="text-xs px-2 py-1 rounded border flex items-center gap-1 transition-colors font-medium
                                     bg-green-50 text-green-700 border-green-200 hover:bg-green-100
                                     dark:bg-green-900/30 dark:text-green-400 dark:border-green-800 dark:hover:bg-green-900/50"><Plus size={12}/> Parça Fiyatı Ekle</button>
                               ) : (
                                   <div className="text-xs px-2 py-1 rounded border font-bold flex items-center gap-1
                                     bg-gray-100 text-gray-600 border-gray-200
                                     dark:bg-dark-bg dark:text-gray-300 dark:border-dark-border">
                                      <span>Sabit:</span>
                                      <PriceEditable value={variant.variantPrice} onSave={(val) => handleInlineUpdateVariant(variant, prod.id, val)} />
                                   </div>
                               )}
                               <button onClick={() => handleDelete('VARIANT', variantId)} className="text-red-400 hover:text-red-500 p-1"><Trash2 size={14}/></button>
                           </div>
                        </div>

                        {/* 3. SEVİYE: PARÇA FİYATLARI (Sadece HasSubParts true ise görünür) */}
                        {variant.hasSubParts && (
                            <ul className="space-y-2">
                            {variant.partPrices?.map((price, pIdx) => (
                                <li key={pIdx} className="flex justify-between items-center text-sm p-2 rounded border border-transparent transition-all
                                  hover:bg-gray-50 hover:border-gray-200
                                  dark:hover:bg-dark-bg dark:hover:border-dark-border">
                                    <div className="flex items-center gap-2"><span className="font-medium text-gray-700 dark:text-gray-300">{price.partName}</span>{price.isExtra && <span className="text-[10px] bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-500 px-1.5 py-0.5 rounded font-bold">Ekstra</span>}</div>
                                    <div className="flex items-center gap-2">
                                        <div className="font-bold text-green-600">
                                            <PriceEditable value={price.price} onSave={(val) => handleInlineUpdatePartPrice(price, variant.id, val)} />
                                        </div>
                                        <button onClick={() => handleDelete('PRICE', price.id)} className="text-gray-400 hover:text-red-500 dark:text-gray-300"><Trash2 size={12}/></button>
                                    </div>
                                </li>
                            ))}
                            {(!variant.partPrices || variant.partPrices.length === 0) && <li className="text-xs text-gray-400 italic text-center py-2">Henüz parça fiyatı girilmedi.</li>}
                            </ul>
                        )}
                      </div>
                    )})}
                    {(!prod.variants || prod.variants.length === 0) && <div className="col-span-2 text-center py-6 text-gray-500 italic rounded-lg border border-dashed
                       bg-white border-gray-300
                       dark:bg-dark-card dark:border-dark-border">Varyant yok.</div>}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* --- MODAL FORM --- */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="w-full max-w-md rounded-2xl shadow-2xl p-6 relative border transition-colors
            bg-white border-gray-200
            dark:bg-dark-card dark:border-dark-border">
            <button onClick={closeModal} className="absolute top-4 right-4 text-gray-400 hover:text-red-500 transition-colors"><X size={20}/></button>
            <h3 className="text-xl font-bold mb-6 border-b pb-3
              text-gray-800 border-gray-200
              dark:text-gray-100 dark:border-gray-700">
                {modalType === 'CATEGORY' && "Kategori Yönetimi"}
                {modalType === 'PRODUCT' && "Yeni Ürün Tanımla"}
                {modalType === 'VARIANT' && "Varyant Ekle"}
                {modalType === 'PRICE' && "Parça Fiyatı Ekle"}
            </h3>
            <form onSubmit={handleSave} className="space-y-4">
                
                {/* KATEGORİ FORMU */}
                {modalType === 'CATEGORY' && (
                    <>
                        <input className="w-full p-3 rounded-lg outline-none focus:ring-2 border transition-colors
                          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
                          dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" placeholder="Kategori Adı" value={formData.name} onChange={e => setFormData({...formData, name: e.target.value})} required />
                        <textarea className="w-full p-3 rounded-lg outline-none focus:ring-2 border transition-colors
                          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
                          dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" placeholder="Açıklama" value={formData.description} onChange={e => setFormData({...formData, description: e.target.value})} />
                    </>
                )}

                {/* ÜRÜN FORMU */}
                {modalType === 'PRODUCT' && (
                    <>
                        <select className="w-full p-3 rounded-lg outline-none focus:ring-2 border transition-colors
                          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
                          dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" value={formData.categoryId} onChange={e => setFormData({...formData, categoryId: e.target.value})} required><option value="">Kategori Seçin</option>{categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}</select>
                        <input className="w-full p-3 rounded-lg outline-none focus:ring-2 border transition-colors
                          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
                          dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" placeholder="Marka (Örn: OLEX)" value={formData.brand} onChange={e => setFormData({...formData, brand: e.target.value})} required />
                        <input className="w-full p-3 rounded-lg outline-none focus:ring-2 border transition-colors
                          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
                          dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" placeholder="Ürün Adı" value={formData.name} onChange={e => setFormData({...formData, name: e.target.value})} required />
                        
                        {/* MİKRON SEÇENEĞİ */}
                        <div className="p-3 rounded-lg border
                          bg-blue-50 border-blue-100
                          dark:bg-brand/10 dark:border-brand/20">
                            <label className="flex items-center gap-3 cursor-pointer">
                                <input type="checkbox" className="w-5 h-5 text-blue-600 dark:text-brand rounded" checked={formData.hasMicron} onChange={e => setFormData({...formData, hasMicron: e.target.checked})} />
                                <span className="font-bold text-blue-700 dark:text-brand">Bu Ürünün Mikron Çeşitleri Var mı?</span>
                            </label>
                            {/* Eğer micron yoksa fiyat sor */}
                            {!formData.hasMicron && (
                                <div className="mt-3 relative animate-in slide-in-from-top-2">
                                    <input type="number" className="w-full p-2 rounded pl-8 outline-none focus:ring-2 border
                                      bg-white border-gray-300 text-gray-900 focus:ring-blue-500
                                      dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" placeholder="Ürün Fiyatı" value={formData.basePrice} onChange={e => setFormData({...formData, basePrice: e.target.value})} required />
                                    <span className="absolute left-2 top-2 text-gray-400">₺</span>
                                </div>
                            )}
                        </div>
                    </>
                )}

                {/* VARYANT FORMU */}
                {modalType === 'VARIANT' && (
                    <>
                        <input className="w-full p-3 rounded-lg outline-none focus:ring-2 border transition-colors
                          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
                          dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" placeholder="Kod / Kalınlık (Örn: 190)" value={formData.thicknessCode} onChange={e => setFormData({...formData, thicknessCode: e.target.value})} required />
                        <input className="w-full p-3 rounded-lg outline-none focus:ring-2 border transition-colors
                          bg-white border-gray-300 text-gray-900 focus:ring-blue-500
                          dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-brand" placeholder="Varyant Adı (Örn: Micron)" value={formData.name} onChange={e => setFormData({...formData, name: e.target.value})} required />
                        
                        {/* ALT PARÇA SEÇENEĞİ */}
                        <div className="p-3 rounded-lg border
                          bg-purple-50 border-purple-100
                          dark:bg-purple-900/20 dark:border-purple-800">
                            <label className="flex items-center gap-3 cursor-pointer">
                                <input type="checkbox" className="w-5 h-5 text-purple-600 rounded" checked={formData.hasSubParts} onChange={e => setFormData({...formData, hasSubParts: e.target.checked})} />
                                <span className="font-bold text-purple-800 dark:text-purple-300">Alt Parçalara Bölünecek mi? (Kaput, Tavan...)</span>
                            </label>
                            {/* Eğer alt parça yoksa tek fiyat sor */}
                            {!formData.hasSubParts && (
                                <div className="mt-3 relative animate-in slide-in-from-top-2">
                                    <input type="number" className="w-full p-2 rounded pl-8 outline-none focus:ring-2 border
                                      bg-white border-gray-300 text-gray-900 focus:ring-green-500
                                      dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-green-500" placeholder="Varyant Fiyatı" value={formData.variantPrice} onChange={e => setFormData({...formData, variantPrice: e.target.value})} required />
                                    <span className="absolute left-2 top-2 text-gray-400">₺</span>
                                </div>
                            )}
                        </div>
                    </>
                )}

                {/* FİYAT FORMU (Sadece Alt Parça Varsa Açılır) */}
                {modalType === 'PRICE' && (
                    <>
                        <input className="w-full p-3 rounded-lg outline-none focus:ring-2 border transition-colors
                          bg-white border-gray-300 text-gray-900 focus:ring-green-500
                          dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-green-500" placeholder="Parça Adı (Örn: Kaput)" value={formData.partName} onChange={e => setFormData({...formData, partName: e.target.value})} required />
                        <div className="relative">
                            <input type="number" className="w-full p-3 rounded-lg pl-8 outline-none focus:ring-2 border transition-colors
                              bg-white border-gray-300 text-gray-900 focus:ring-green-500
                              dark:border-dark-border dark:bg-dark-bg dark:text-white dark:focus:ring-green-500" placeholder="Fiyat" value={formData.price} onChange={e => setFormData({...formData, price: parseFloat(e.target.value)})} required />
                            <span className="absolute left-3 top-3.5 text-gray-400">₺</span>
                        </div>
                        <label className="flex items-center gap-3 p-3 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-dark-hover
                          border-gray-200 dark:border-gray-700">
                            <input type="checkbox" className="w-5 h-5 text-blue-600 rounded" checked={formData.isExtra} onChange={e => setFormData({...formData, isExtra: e.target.checked})} />
                            <span className="text-gray-700 dark:text-gray-300 font-medium">Ekstra İşlem mi?</span>
                        </label>
                    </>
                )}

                <button type="submit" className="w-full py-3 rounded-lg font-bold flex justify-center items-center gap-2 shadow-md transition-all
                  bg-blue-600 text-white hover:bg-blue-700
                  dark:bg-brand dark:text-white dark:hover:bg-brand-dark"><Save size={18} /> Kaydet</button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default SettingsView;
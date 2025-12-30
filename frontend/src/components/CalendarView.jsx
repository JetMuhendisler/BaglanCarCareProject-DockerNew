import React, { useState } from "react";
import { ChevronLeft, ChevronRight, Circle } from "lucide-react";

/**
 * @param {Object[]} orders - List of orders to display on calendar
 * @param {Function} onDateSelect - Callback when a date is clicked (YYYY-MM-DD)
 * @param {string} selectedDate - Currently selected date (YYYY-MM-DD)
 */
const CalendarView = ({ orders = [], onDateSelect, selectedDate, showDetails = true }) => {
  const [currentDate, setCurrentDate] = useState(selectedDate ? new Date(selectedDate) : new Date());

  // Helper to get days in month
  const getDaysInMonth = (year, month) => new Date(year, month + 1, 0).getDate();
  const getFirstDayOfMonth = (year, month) => {
      // 0 = Sunday, 1 = Monday. We want Monday start.
      let day = new Date(year, month, 1).getDay();
      return day === 0 ? 6 : day - 1; 
  };

  const year = currentDate.getFullYear();
  const month = currentDate.getMonth();

  const daysInMonth = getDaysInMonth(year, month);
  const firstDay = getFirstDayOfMonth(year, month);

  // Month Names (Turkish)
  const monthNames = [
    "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
    "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"
  ];

  const handlePrevMonth = () => setCurrentDate(new Date(year, month - 1, 1));
  const handleNextMonth = () => setCurrentDate(new Date(year, month + 1, 1));

  // Determine if a day is selected
  const isSelected = (d) => {
      if (!selectedDate) return false;
      const target = new Date(selectedDate);
      return target.getDate() === d && target.getMonth() === month && target.getFullYear() === year;
  };
    
  // Check if today
  const isToday = (d) => {
      const today = new Date();
      return today.getDate() === d && today.getMonth() === month && today.getFullYear() === year;
  }

  // Get orders for a specific day
  const getOrdersForDay = (day) => {
    const dateStr = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    return orders.filter(o => {
        // Handle various date formats from backend
        // rawDate is reliably ISO from Dashboard
        const oDate = new Date(o.rawDate || o.date || o.Date || o.TransactionDate);
        return !isNaN(oDate.getTime()) && oDate.toISOString().split('T')[0] === dateStr;
    });
  };

  return (
    <div className="bg-white dark:bg-dark-card rounded-xl border border-gray-200 dark:border-dark-border shadow-sm overflow-hidden">
        {/* Header */}
        <div className="flex justify-between items-center p-4 border-b border-gray-200 dark:border-dark-border bg-gray-50 dark:bg-dark-hover">
            <button onClick={handlePrevMonth} className="p-2 hover:bg-gray-200 dark:hover:bg-dark-bg rounded-lg transition-colors">
                <ChevronLeft size={20} className="text-gray-600 dark:text-gray-300"/>
            </button>
            <h2 className="text-lg font-bold text-gray-800 dark:text-gray-100">{monthNames[month]} {year}</h2>
            <button onClick={handleNextMonth} className="p-2 hover:bg-gray-200 dark:hover:bg-dark-bg rounded-lg transition-colors">
                <ChevronRight size={20} className="text-gray-600 dark:text-gray-300"/>
            </button>
        </div>

        {/* Days Header */}
        <div className="grid grid-cols-7 border-b border-gray-200 dark:border-dark-border">
            {["Pzt", "Sal", "Çar", "Per", "Cum", "Cmt", "Paz"].map(day => (
                <div key={day} className="py-2 text-center text-xs font-semibold text-gray-500 uppercase tracking-wider bg-gray-50/50 dark:bg-dark-card">
                    {day}
                </div>
            ))}
        </div>

        {/* Calendar Grid */}
        <div className="grid grid-cols-7 auto-rows-fr">
            {/* Empty cells for previous month */}
            {Array.from({ length: firstDay }).map((_, i) => (
                <div key={`empty-${i}`} className="h-16 md:h-20 border-b border-r border-gray-100 dark:border-dark-border/50 bg-gray-50/30 dark:bg-dark-bg/20"></div>
            ))}

            {/* Days */}
            {Array.from({ length: daysInMonth }).map((_, i) => {
                const day = i + 1;
                const dayOrders = getOrdersForDay(day);
                const selected = isSelected(day);
                const today = isToday(day);
                const dateStr = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;

                return (
                    <div 
                        key={day} 
                        onClick={() => onDateSelect && onDateSelect(dateStr)}
                        className={`h-16 md:h-20 border-b border-r border-gray-100 dark:border-dark-border/50 p-1 relative flex flex-col gap-0.5 transition-all cursor-pointer hover:bg-blue-50/50 dark:hover:bg-brand/5
                            ${selected ? 'bg-blue-50 ring-2 ring-inset ring-blue-500 dark:bg-brand/10 dark:ring-brand' : ''}
                            ${today ? 'bg-yellow-50/50' : ''}
                        `}
                    >
                        <span className={`text-xs font-medium w-6 h-6 flex items-center justify-center rounded-full
                            ${today ? 'bg-blue-600 text-white shadow-md dark:bg-brand' : 'text-gray-700 dark:text-gray-400'}
                        `}>
                            {day}
                        </span>

                        <div className="flex-1 overflow-hidden flex flex-col gap-0.5 mt-0.5">
                            {dayOrders.slice(0, 2).map((o, idx) => (
                                <div key={idx} className="flex items-center gap-1 text-[9px] bg-white border border-gray-200 rounded px-1 py-0.5 truncate shadow-sm dark:bg-dark-bg dark:border-dark-border dark:text-gray-300">
                                    <div className={`w-1 h-1 rounded-full flex-shrink-0 
                                        ${(o.status||"").includes("Bekliyor") ? "bg-yellow-500" : 
                                          (o.status||"").includes("Tamam") ? "bg-green-500" : 
                                          (o.status||"").includes("İşlemde") ? "bg-blue-500" : "bg-gray-400"}`}></div>
                                    <span className="truncate flex-1">{o.plate}</span>
                                </div>
                            ))}
                            {dayOrders.length > 2 && <div className="text-[9px] text-gray-400 pl-1">+{dayOrders.length - 2}</div>}
                        </div>
                    </div>
                );
            })}
        </div>

        {/* Selected Day Details */}
        {showDetails && selectedDate && (
             <div className="border-t border-gray-200 dark:border-dark-border p-4 bg-gray-50/50 dark:bg-dark-bg/20">
                 <h4 className="text-sm font-bold text-gray-700 dark:text-gray-200 mb-3 flex items-center gap-2">
                     <span className="w-2 h-2 rounded-full bg-blue-600 dark:bg-brand"></span>
                     {new Date(selectedDate).toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', weekday: 'long' })} İşlemleri
                 </h4>
                 {(() => {
                     const selectedOrders = orders.filter(o => {
                        const oDate = new Date(o.rawDate || o.date || o.Date || o.TransactionDate);
                        return !isNaN(oDate.getTime()) && oDate.toISOString().split('T')[0] === selectedDate;
                     });

                     if (selectedOrders.length === 0) return <p className="text-sm text-gray-400 italic">Bu tarihte planlanmış işlem bulunmuyor.</p>;

                     return (
                         <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                             {selectedOrders.map((o, idx) => (
                                 <div key={idx} className="bg-white dark:bg-dark-card border border-gray-200 dark:border-dark-border p-3 rounded-lg shadow-sm flex justify-between items-center">
                                     <div>
                                         <div className="font-bold text-gray-800 dark:text-gray-100 flex items-center gap-2">
                                             {o.plate} 
                                             <span className={`text-[10px] px-1.5 py-0.5 rounded border 
                                                ${(o.status||"").includes("Bekliyor") ? "bg-orange-50 text-orange-700 border-orange-200" : 
                                                  (o.status||"").includes("Tamam") ? "bg-green-50 text-green-700 border-green-200" : 
                                                  "bg-blue-50 text-blue-700 border-blue-200"}`}>{o.status}</span>
                                         </div>
                                         <div className="text-xs text-gray-500 dark:text-gray-400">{o.brand} {o.model} • {o.customer}</div>
                                     </div>
                                 </div>
                             ))}
                         </div>
                     );
                 })()}
             </div>
        )}
    </div>
  );
};

export default CalendarView;

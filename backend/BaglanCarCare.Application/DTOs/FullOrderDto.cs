using System;
using System.Collections.Generic;

namespace BaglanCarCare.Application.DTOs
{
    // 1. CREATE: Yeni Sipariş (Burası DOĞRU)
    public class CreateOrderDto
    {
        public string CustomerName { get; set; } = string.Empty;
        public string CustomerPhone { get; set; } = string.Empty;
        public string? CustomerEmail { get; set; }

        public string PlateNumber { get; set; } = string.Empty;
        public string Brand { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string? Color { get; set; }
        public string? Year { get; set; }

        public List<int> PersonnelIds { get; set; } = new();
        public DateTime ReceivedDate { get; set; }
        public DateTime TargetDate { get; set; }
        public decimal TotalPrice { get; set; }
        public string PaymentMethod { get; set; } = string.Empty;
        public bool IsPaid { get; set; }

        public List<OrderItemDto> SelectedServices { get; set; } = new();
    }

    // Ortak Kullanılan Hizmet Detay Objesi
    public class OrderItemDto
    {
        public string Category { get; set; } = string.Empty;
        public string Product { get; set; } = string.Empty;
        public string? Spec { get; set; } // Varyant / Mikron
        public string Part { get; set; } = string.Empty;
        public decimal Price { get; set; }
    }

    // 2. LIST: Listeleme (GÜNCELLENDİ)
    public class OrderListDto
    {
        public int Id { get; set; }
        public string CustomerInfo { get; set; } = string.Empty;
        public string CustomerPhone { get; set; } = string.Empty;
        public string VehicleInfo { get; set; } = string.Empty;
        public string Brand { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string? Color { get; set; }
        public string? Year { get; set; }
        public string? CustomerEmail { get; set; }
        public string Plate { get; set; } = string.Empty;
        public decimal TotalPrice { get; set; }
        public string Status { get; set; } = string.Empty;
        public string StatusTr { get; set; } = string.Empty;
        public bool IsPaid { get; set; }
        public DateTime Date { get; set; }
        public string PersonnelNames { get; set; } = string.Empty;

        // ESKİ: public List<string> SummaryList { get; set; } = new();

        // YENİ: Frontend'in detayları görebilmesi için bu gereklidir!
        public List<OrderItemDto> SelectedServices { get; set; } = new();

        public List<int> PersonnelIds { get; set; } = new();
    }

    // 3. UPDATE (Aynen Kalabilir)
    public class UpdateOrderDto
    {
        public int OrderId { get; set; }
        public string? Description { get; set; }
        public int StatusId { get; set; }
        public List<int> PersonnelIds { get; set; } = new();
        public bool IsPaid { get; set; }
        
        // YENİ: Hizmet ve Fiyat Güncelleme Desteği
        public List<OrderItemDto>? SelectedServices { get; set; }
        public decimal? TotalPrice { get; set; }
    }

    // 4. SEARCH (Aynen Kalabilir)
    public class CustomerVehicleSearchDto
    {
        public bool Found { get; set; }
        public string CustomerName { get; set; } = string.Empty;
        public string Phone { get; set; } = string.Empty;
        public string Plate { get; set; } = string.Empty;
        public string Brand { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
    }
}
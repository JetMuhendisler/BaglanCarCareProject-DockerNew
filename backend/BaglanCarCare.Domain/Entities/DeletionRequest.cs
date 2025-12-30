using BaglanCarCare.Domain.Common;
using System;

namespace BaglanCarCare.Domain.Entities
{
    public class DeletionRequest : BaseEntity
    {
        public int RequesterId { get; set; }
        public string RequesterName { get; set; } // Performans için isim de tutalım
        public string TargetEntityName { get; set; } // "Order", "Vehicle", vb.
        public int TargetId { get; set; }
        public string Note { get; set; } // "Yanlış giriş yaptım" vb.
        public string Status { get; set; } = "Pending"; // Pending, Approved, Rejected
        public DateTime? ProcessedDate { get; set; }
    }
}

using BaglanCarCare.Domain.Common;
using BaglanCarCare.Domain.Enums;
using System;
using System.Collections.Generic;

namespace BaglanCarCare.Domain.Entities
{
    public class ServiceTransaction : BaseEntity
    {
        public DateTime TransactionDate { get; set; } = DateTime.UtcNow;
        public DateTime AppointmentDate { get; set; } // Bu alan eksikti

        public string? Description { get; set; }
        public decimal TotalPrice { get; set; }
        public PaymentStatus PaymentStatus { get; set; }
        public TransactionStatus Status { get; set; }
        public PaymentMethod PaymentMethod { get; set; }

        public int VehicleId { get; set; }
        public Vehicle? Vehicle { get; set; }

        // Hata veren 'Personnels' listesi burası:
        public ICollection<Personnel> Personnels { get; set; } = new List<Personnel>();

        // Hata veren 'TransactionItems' listesi burası:
        public ICollection<ServiceTransactionItem> TransactionItems { get; set; } = new List<ServiceTransactionItem>();
    }
}
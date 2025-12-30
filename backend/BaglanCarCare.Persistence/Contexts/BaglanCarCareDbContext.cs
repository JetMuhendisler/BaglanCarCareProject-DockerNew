using BaglanCarCare.Domain.Common;
using BaglanCarCare.Domain.Entities;
using BaglanCarCare.Domain.Entities.Catalog;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading;
using System.Threading.Tasks;
namespace BaglanCarCare.Persistence.Contexts
{
    public class BaglanCarCareDbContext : DbContext
    {
        public BaglanCarCareDbContext(DbContextOptions<BaglanCarCareDbContext> o) : base(o) { }
        public DbSet<User> Users { get; set; }
        public DbSet<Personnel> Personnels { get; set; }
        public DbSet<Customer> Customers { get; set; }
        public DbSet<Vehicle> Vehicles { get; set; }
        public DbSet<ServiceTransaction> ServiceTransactions { get; set; }
        public override Task<int> SaveChangesAsync(CancellationToken c = default) { foreach (var e in ChangeTracker.Entries<BaseEntity>()) if (e.State == EntityState.Added) { e.Entity.CreatedDate = DateTime.UtcNow; e.Entity.IsDeleted = false; } return base.SaveChangesAsync(c); }
        protected override void OnModelCreating(ModelBuilder m) { m.ApplyConfigurationsFromAssembly(typeof(BaglanCarCareDbContext).Assembly); base.OnModelCreating(m); }
        // DbSet listesine şunu ekleyin:
        public DbSet<ServiceTransactionItem> ServiceTransactionItems { get; set; }
        // DbSet listesine ekle:
        public DbSet<ExpenseRecord> ExpenseRecords { get; set; }
        public DbSet<Category> Categories { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<ProductVariant> ProductVariants { get; set; }
        public DbSet<ProductPartPrice> ProductPartPrices { get; set; }
        public DbSet<DeletionRequest> DeletionRequests { get; set; }
    }
}
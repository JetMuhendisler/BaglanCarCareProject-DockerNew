using BaglanCarCare.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace BaglanCarCare.Persistence.Configurations
{
    public class ServiceTransactionConfiguration : IEntityTypeConfiguration<ServiceTransaction>
    {
        public void Configure(EntityTypeBuilder<ServiceTransaction> builder)
        {
            // Araç İlişkisi
            builder.HasOne(x => x.Vehicle)
                   .WithMany(x => x.ServiceTransactions)
                   .HasForeignKey(x => x.VehicleId);

            // DÜZELTME: Personel ile artık Çoka-Çok ilişki var
            // Eğer burada eski .HasOne(x => x.Personnel) kodu varsa HATA VERİR.
            builder.HasMany(x => x.Personnels)
                   .WithMany(x => x.ServiceTransactions);


        }
    }
}
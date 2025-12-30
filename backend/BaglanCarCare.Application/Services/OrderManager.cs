using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Interfaces.Repositories;
using BaglanCarCare.Application.Interfaces.Services;
using BaglanCarCare.Application.Wrappers;
using BaglanCarCare.Domain.Entities;
using BaglanCarCare.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BaglanCarCare.Application.Services
{
    public class OrderManager : IOrderService
    {
        private readonly IGenericRepository<ServiceTransaction> _transRepo;
        private readonly IGenericRepository<Customer> _custRepo;
        private readonly IGenericRepository<Vehicle> _vehicleRepo;
        private readonly IGenericRepository<Personnel> _personnelRepo;

        public OrderManager(
            IGenericRepository<ServiceTransaction> transRepo,
            IGenericRepository<Customer> custRepo,
            IGenericRepository<Vehicle> vehicleRepo,
            IGenericRepository<Personnel> personnelRepo)
        {
            _transRepo = transRepo;
            _custRepo = custRepo;
            _vehicleRepo = vehicleRepo;
            _personnelRepo = personnelRepo;
        }

        // 1. LIST
        public async Task<ServiceResponse<List<OrderListDto>>> GetAllOrdersAsync()
        {
            var data = await _transRepo.GetAllAsync();

            var dtoList = data.OrderByDescending(x => x.TransactionDate).Select(x => new OrderListDto
            {
                Id = x.Id,
                CustomerInfo = x.Vehicle?.Customer != null ? x.Vehicle.Customer.FirstName + " " + x.Vehicle.Customer.LastName : "Bilinmiyor",
                CustomerPhone = x.Vehicle?.Customer?.PhoneNumber ?? "-",
                CustomerEmail = x.Vehicle?.Customer?.Email,
                VehicleInfo = x.Vehicle != null ? x.Vehicle.Brand + " " + x.Vehicle.Model : "Araç Silinmiş",
                Brand = x.Vehicle?.Brand ?? "-",
                Model = x.Vehicle?.Model ?? "-",
                Color = x.Vehicle?.Color,
                Year = x.Vehicle?.Year.ToString(),
                Plate = x.Vehicle?.PlateNumber ?? "-",
                TotalPrice = x.TotalPrice,
                Status = x.Status.ToString(),
                IsPaid = x.PaymentStatus == PaymentStatus.Paid,
                StatusTr = x.Status switch
                {
                    TransactionStatus.Pending => "Bekliyor",
                    TransactionStatus.InProgress => "İşlemde",
                    TransactionStatus.Completed => "Tamamlandı",
                    TransactionStatus.Cancelled => "İptal",
                    _ => "Bilinmiyor"
                },
                Date = x.TransactionDate,

                // --- 1. DÜZELTME: İsim Birleştirme ve Null Kontrolü ---
                PersonnelNames = x.Personnels != null && x.Personnels.Any()
                    ? string.Join(", ", x.Personnels.Select(p => (p.FirstName + " " + (p.LastName ?? "")).Trim()))
                    : "Atanmadı",

                // --- 2. DÜZELTME: ID Listesi (Düzenleme ekranı için gerekli) ---
                PersonnelIds = x.Personnels != null ? x.Personnels.Select(p => p.Id).ToList() : new List<int>(),

                // --- 3. Hizmet Detayları ---
                SelectedServices = x.TransactionItems != null
                    ? x.TransactionItems.Select(i => new OrderItemDto
                    {
                        Category = i.Category,
                        Product = i.Name,
                        Part = i.SelectedParts,
                        Price = i.Price,
                        Spec = ""
                    }).ToList()
                    : new List<OrderItemDto>()

            }).ToList();

            return new ServiceResponse<List<OrderListDto>>(dtoList);
        }

        // 2. CREATE
        public async Task<ServiceResponse<int>> CreateOrderAsync(CreateOrderDto r)
        {
            // Müşteri
            var customer = (await _custRepo.GetAsync(c => c.PhoneNumber == r.CustomerPhone)).FirstOrDefault();
            if (customer == null)
            {
                customer = new Customer
                {
                    FirstName = r.CustomerName,
                    LastName = "",
                    PhoneNumber = r.CustomerPhone,
                    Email = r.CustomerEmail
                };
                await _custRepo.AddAsync(customer);
            }

            // Araç
            var vehicle = (await _vehicleRepo.GetAsync(v => v.PlateNumber == r.PlateNumber)).FirstOrDefault();
            if (vehicle == null)
            {
                vehicle = new Vehicle
                {
                    PlateNumber = r.PlateNumber,
                    Brand = r.Brand,
                    Model = r.Model,
                    Color = r.Color,
                    Year = int.TryParse(r.Year, out int y) ? y : 0,
                    CustomerId = customer.Id
                };
                await _vehicleRepo.AddAsync(vehicle);
            }

            // İşlem
            var transaction = new ServiceTransaction
            {
                VehicleId = vehicle.Id,

                TransactionDate = r.ReceivedDate.ToUniversalTime(),
                AppointmentDate = r.TargetDate.ToUniversalTime(),
                TotalPrice = r.TotalPrice,
                Description = "Sipariş Kaydı",
                Status = TransactionStatus.Pending,
                PaymentMethod = r.PaymentMethod == "Kredi Kartı" ? PaymentMethod.CreditCard : PaymentMethod.Cash,
                PaymentStatus = r.IsPaid ? PaymentStatus.Paid : PaymentStatus.Unpaid,
                Personnels = new List<Personnel>(),
                TransactionItems = new List<ServiceTransactionItem>()
            };

            // Personel
            // Personel (Çoklu Seçim)
            if (r.PersonnelIds != null && r.PersonnelIds.Any())
            {
                foreach (var pid in r.PersonnelIds)
                {
                    var staff = await _personnelRepo.GetByIdAsync(pid);
                    if (staff != null) transaction.Personnels.Add(staff);
                }
            }

            // Hizmet Kalemleri
            if (r.SelectedServices != null)
            {
                foreach (var item in r.SelectedServices)
                {
                    transaction.TransactionItems.Add(new ServiceTransactionItem
                    {
                        Category = item.Category,
                        Name = item.Product + (string.IsNullOrEmpty(item.Spec) ? "" : $" ({item.Spec})"),
                        SelectedParts = item.Part,
                        Price = item.Price
                    });
                }
            }

            await _transRepo.AddAsync(transaction);
            return new ServiceResponse<int>(transaction.Id);
        }

        // 3. UPDATE
        public async Task<ServiceResponse<bool>> UpdateOrderDetailsAsync(UpdateOrderDto r)
        {
            var list = await _transRepo.GetAllAsync();
            var transaction = list.FirstOrDefault(x => x.Id == r.OrderId);

            if (transaction == null)
                return new ServiceResponse<bool>("Sipariş bulunamadı.", false);

            if (!string.IsNullOrEmpty(r.Description)) transaction.Description = r.Description;
            transaction.Status = (TransactionStatus)r.StatusId;
            transaction.PaymentStatus = r.IsPaid ? PaymentStatus.Paid : PaymentStatus.Unpaid;
            transaction.Personnels.Clear();
            if (r.PersonnelIds != null && r.PersonnelIds.Any())
            {
                var newStaff = await _personnelRepo.GetAsync(p => r.PersonnelIds.Contains(p.Id));
                foreach (var staff in newStaff) transaction.Personnels.Add(staff);
            }

            // HİZMET GÜNCELLEME (YENİ)
            if (r.SelectedServices != null)
            {
                transaction.TransactionItems.Clear(); // Önce temizle
                foreach (var item in r.SelectedServices)
                {
                    transaction.TransactionItems.Add(new ServiceTransactionItem
                    {
                        Category = item.Category,
                        Name = item.Product,
                        SelectedParts = item.Part,
                        Price = item.Price
                    });
                }
            }

            // FİYAT GÜNCELLEME (YENİ)
            if (r.TotalPrice.HasValue)
            {
                transaction.TotalPrice = r.TotalPrice.Value;
            }

            await _transRepo.UpdateAsync(transaction);
            return new ServiceResponse<bool>(true);
        }

        // 4. DELETE
        public async Task<ServiceResponse<bool>> DeleteOrderAsync(int id)
        {
            var entity = await _transRepo.GetByIdAsync(id);
            if (entity == null) return new ServiceResponse<bool>("Sipariş bulunamadı", false);
            await _transRepo.DeleteAsync(entity);
            return new ServiceResponse<bool>(true);
        }

        // 5. SEARCH
        public async Task<ServiceResponse<CustomerVehicleSearchDto>> SearchByPhoneOrPlateAsync(string text)
        {
            var vehicle = (await _vehicleRepo.GetAsync(v => v.PlateNumber == text)).FirstOrDefault();
            if (vehicle != null)
            {
                var owner = await _custRepo.GetByIdAsync(vehicle.CustomerId);
                return new ServiceResponse<CustomerVehicleSearchDto>(new CustomerVehicleSearchDto
                {
                    Found = true,
                    Plate = vehicle.PlateNumber,
                    Brand = vehicle.Brand,
                    Model = vehicle.Model,
                    CustomerName = owner != null ? owner.FirstName + " " + owner.LastName : "",
                    Phone = owner?.PhoneNumber ?? ""
                });
            }
            var customer = (await _custRepo.GetAsync(c => c.PhoneNumber == text)).FirstOrDefault();
            if (customer != null)
            {
                return new ServiceResponse<CustomerVehicleSearchDto>(new CustomerVehicleSearchDto
                {
                    Found = true,
                    CustomerName = customer.FirstName + " " + customer.LastName,
                    Phone = customer.PhoneNumber
                });
            }
            return new ServiceResponse<CustomerVehicleSearchDto>(new CustomerVehicleSearchDto { Found = false });
        }
    }
}
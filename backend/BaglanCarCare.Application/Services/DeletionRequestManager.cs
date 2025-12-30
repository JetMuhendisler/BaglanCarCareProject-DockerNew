using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Interfaces.Repositories;
using BaglanCarCare.Application.Interfaces.Services;
using BaglanCarCare.Application.Wrappers;
using BaglanCarCare.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BaglanCarCare.Application.Services
{
    public class DeletionRequestManager : IDeletionRequestService
    {
        private readonly IGenericRepository<DeletionRequest> _repo;
        // İhtiyaç duyulacak diğer servisler (Onay durumunda silme yapmak için)
        private readonly IOrderService _orderService;
        private readonly IExpenseService _expenseService;
        private readonly ICatalogService _catalogService;
        private readonly IPersonnelService _personnelService;

        public DeletionRequestManager(
            IGenericRepository<DeletionRequest> repo,
            IOrderService orderService,
            IExpenseService expenseService,
            ICatalogService catalogService,
            IPersonnelService personnelService)
        {
            _repo = repo;
            _orderService = orderService;
            _expenseService = expenseService;
            _catalogService = catalogService;
            _personnelService = personnelService;
        }

        public async Task<ServiceResponse<int>> CreateRequestAsync(CreateDeletionRequestDto request, int requesterId, string requesterName)
        {
            var entity = new DeletionRequest
            {
                RequesterId = requesterId,
                RequesterName = requesterName,
                TargetEntityName = request.TargetEntityName,
                TargetId = request.TargetId,
                Note = request.Note,
                Status = "Pending"
            };
            await _repo.AddAsync(entity);
            return new ServiceResponse<int>(entity.Id, "Silme talebi oluşturuldu. Admin onayı bekleniyor.");
        }

        public async Task<ServiceResponse<List<DeletionRequestListDto>>> GetAllPendingRequestsAsync()
        {
            var list = await _repo.GetAsync(x => x.Status == "Pending");
            var dtoList = list.Select(x => new DeletionRequestListDto
            {
                Id = x.Id,
                RequesterName = x.RequesterName,
                TargetEntityName = x.TargetEntityName,
                TargetId = x.TargetId,
                Note = x.Note,
                Status = x.Status,
                CreatedDate = x.CreatedDate
            }).OrderByDescending(x => x.CreatedDate).ToList();

            return new ServiceResponse<List<DeletionRequestListDto>>(dtoList);
        }

        public async Task<ServiceResponse<bool>> ApproveRequestAsync(int requestId)
        {
            var request = await _repo.GetByIdAsync(requestId);
            if (request == null) return new ServiceResponse<bool>("Talep bulunamadı.", false);

            if (request.Status != "Pending") return new ServiceResponse<bool>("Bu talep zaten işlenmiş.", false);

            // Gerçek silme işlemini yap
            bool deleteResult = false;
            try
            {
                switch (request.TargetEntityName)
                {
                    case "Order":
                        // OrderService'de DeleteAsync var mı? Varsa çağır.
                         await _orderService.DeleteOrderAsync(request.TargetId);
                        deleteResult = true; 
                        break;
                    case "Expense":
                        await _expenseService.DeleteAsync(request.TargetId);
                        deleteResult = true;
                        break;
                    case "Category": // Katalog
                        await _catalogService.DeleteCategoryAsync(request.TargetId);
                        deleteResult = true;
                        break;
                    case "Product": // Katalog
                        await _catalogService.DeleteProductAsync(request.TargetId);
                        deleteResult = true;
                        break;
                    case "Personnel": // Personel
                         await _personnelService.DeleteAsync(request.TargetId);
                        deleteResult = true;
                        break;
                    default:
                        return new ServiceResponse<bool>("Bilinmeyen hedef tipi.", false);
                }
            }
            catch (Exception ex)
            {
                return new ServiceResponse<bool>($"Silme işlemi sırasında hata: {ex.Message}", false);
            }

            if (deleteResult)
            {
                request.Status = "Approved";
                request.ProcessedDate = DateTime.UtcNow;
                await _repo.UpdateAsync(request);
                return new ServiceResponse<bool>(true, "Talep onaylandı ve öğe silindi.");
            }
            return new ServiceResponse<bool>("Silme başarısız oldu.", false);
        }

        public async Task<ServiceResponse<bool>> RejectRequestAsync(int requestId)
        {
            var request = await _repo.GetByIdAsync(requestId);
            if (request == null) return new ServiceResponse<bool>("Talep bulunamadı.", false);

            request.Status = "Rejected";
            request.ProcessedDate = DateTime.UtcNow;
            await _repo.UpdateAsync(request);

            return new ServiceResponse<bool>(true, "Talep reddedildi.");
        }
    }
}

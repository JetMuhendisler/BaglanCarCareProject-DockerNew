using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Wrappers;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BaglanCarCare.Application.Interfaces.Services
{
    public interface IDeletionRequestService
    {
        Task<ServiceResponse<int>> CreateRequestAsync(CreateDeletionRequestDto request, int requesterId, string requesterName);
        Task<ServiceResponse<List<DeletionRequestListDto>>> GetAllPendingRequestsAsync();
        Task<ServiceResponse<bool>> ApproveRequestAsync(int requestId);
        Task<ServiceResponse<bool>> RejectRequestAsync(int requestId);
    }
}

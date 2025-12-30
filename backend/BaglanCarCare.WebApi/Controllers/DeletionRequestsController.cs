using BaglanCarCare.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace BaglanCarCare.WebApi.Controllers
{
    [Authorize(Roles = "Admin")]
    [ApiController]
    [Route("api/deletion-requests")]
    public class DeletionRequestsController : ControllerBase
    {
        private readonly IDeletionRequestService _service;

        public DeletionRequestsController(IDeletionRequestService service)
        {
            _service = service;
        }

        [HttpGet("pending")]
        public async Task<IActionResult> GetPendingRequests()
        {
            return Ok(await _service.GetAllPendingRequestsAsync());
        }

        [HttpPost("approve/{id}")]
        public async Task<IActionResult> ApproveRequest(int id)
        {
            return Ok(await _service.ApproveRequestAsync(id));
        }

        [HttpPost("reject/{id}")]
        public async Task<IActionResult> RejectRequest(int id)
        {
            return Ok(await _service.RejectRequestAsync(id));
        }
    }
}

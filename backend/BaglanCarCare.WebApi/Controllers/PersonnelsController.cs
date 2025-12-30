using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
namespace BaglanCarCare.WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/personel")]
    public class PersonnelsController : ControllerBase
    {
        private readonly IPersonnelService _s; public PersonnelsController(IPersonnelService s) { _s = s; }

        [HttpGet] 
        public async Task<IActionResult> Get([FromQuery] string? search) => Ok(await _s.GetAllAsync(search));

        [Authorize(Roles = "Admin")]
        [HttpPost] 
        public async Task<IActionResult> Post(CreatePersonnelDto r) => Ok(await _s.CreateAsync(r));

        [Authorize(Roles = "Admin")]
        [HttpPut] 
        public async Task<IActionResult> Put(UpdatePersonnelDto r) => Ok(await _s.UpdateAsync(r));

        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}")] 
        public async Task<IActionResult> Delete(int id) => Ok(await _s.DeleteAsync(id));
    }
}
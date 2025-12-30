using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
namespace BaglanCarCare.WebApi.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _s; public AuthController(IAuthService s) { _s = s; }
        [HttpPost("login")] public async Task<IActionResult> Login(LoginDto r) => Ok(await _s.LoginAsync(r));
        
        [Authorize(Roles = "Admin")]
        [HttpPost("register")] public async Task<IActionResult> Register(RegisterDto r) => Ok(await _s.RegisterAsync(r));
        
        [Authorize(Roles = "Admin")]
        [HttpGet("users")] public async Task<IActionResult> GetUsers() => Ok(await _s.GetAllUsersAsync());

        [Authorize(Roles = "Admin")]
        [HttpDelete("users/{id}")] public async Task<IActionResult> DeleteUser(int id) => Ok(await _s.DeleteUserAsync(id));
    }
}
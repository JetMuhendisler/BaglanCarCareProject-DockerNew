using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Wrappers;
using System.Threading.Tasks;
namespace BaglanCarCare.Application.Interfaces.Services
{
    public interface IAuthService 
    { 
        Task<ServiceResponse<TokenDto>> LoginAsync(LoginDto request); 
        Task<ServiceResponse<int>> RegisterAsync(RegisterDto request);
        Task<ServiceResponse<System.Collections.Generic.List<UserListDto>>> GetAllUsersAsync();
        Task<ServiceResponse<bool>> DeleteUserAsync(int id);
    }
}
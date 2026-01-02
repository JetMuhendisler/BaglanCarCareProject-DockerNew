using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Interfaces.Repositories;
using BaglanCarCare.Application.Interfaces.Services;
using BaglanCarCare.Application.Wrappers;
using BaglanCarCare.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
namespace BaglanCarCare.Application.Services
{
    public class AuthManager : IAuthService
    {
        private readonly IGenericRepository<User> _repo; private readonly IConfiguration _config;
        public AuthManager(IGenericRepository<User> repo, IConfiguration config) { _repo = repo; _config = config; }
        public async Task<ServiceResponse<TokenDto>> LoginAsync(LoginDto r)
        {
            Console.WriteLine($"[DEBUG] Login attempt for: {r.Username}");
            var user = (await _repo.GetAsync(u => u.Username == r.Username)).FirstOrDefault();
            Console.WriteLine($"[DEBUG] User found: {user != null}");

            if (user == null) return new ServiceResponse<TokenDto>("Kullanıcı adı veya şifre hatalı", false);

            // Lockout Check
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
            {
                var timeLeft = Math.Ceiling((user.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes);
                return new ServiceResponse<TokenDto>($"Hesabınız kilitlendi. Lütfen {timeLeft} dakika sonra tekrar deneyin.", false);
            }

            if (user.PasswordHash != r.Password) 
            {
                user.FailedLoginAttempts++;
                var lockoutThreshold = int.Parse(_config["JwtSettings:LockoutThreshold"] ?? "5");

                if (user.FailedLoginAttempts >= lockoutThreshold)
                {
                    var lockoutMinutes = int.Parse(_config["JwtSettings:LockoutMinutes"] ?? "15");
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(lockoutMinutes);
                    user.FailedLoginAttempts = 0; // Reset attempts after locking
                    await _repo.UpdateAsync(user);
                    return new ServiceResponse<TokenDto>($"Çok fazla başarısız deneme. Hesabınız {lockoutMinutes} dakika kilitlendi.", false);
                }

                await _repo.UpdateAsync(user);
                return new ServiceResponse<TokenDto>("Kullanıcı adı veya şifre hatalı", false);
            }

            // Successful Login
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            Console.WriteLine("[DEBUG] Updating user stats...");
            await _repo.UpdateAsync(user);
            Console.WriteLine("[DEBUG] User stats updated. Generating token...");

            var secretKey = _config["JwtSettings:SecretKey"] ?? "BuEnAz32KarakterlikCokGizliBirSifreOlmali123456";
            var expiryMinutes = double.Parse(_config["JwtSettings:ExpiryMinutes"] ?? "60");
            var expiresAt = DateTime.UtcNow.AddMinutes(expiryMinutes); // Calculate expiration once
            var key = Encoding.ASCII.GetBytes(secretKey);
            var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, user.Username), new Claim(ClaimTypes.Role, user.Role) }),
                Expires = expiresAt,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            }));
            Console.WriteLine("[DEBUG] Token generated successfully.");
            return new ServiceResponse<TokenDto>(new TokenDto { Token = token, Role = user.Role, FullName = user.FullName, Expiration = expiresAt });
        }
        public async Task<ServiceResponse<int>> RegisterAsync(RegisterDto r) { var u = new User { Username = r.Username, PasswordHash = r.Password, FullName = r.FullName, Role = r.Role }; await _repo.AddAsync(u); return new ServiceResponse<int>(u.Id); }
        
        public async Task<ServiceResponse<System.Collections.Generic.List<UserListDto>>> GetAllUsersAsync()
        {
            var users = await _repo.GetAllAsync();
            var dtos = users.Select(u => new UserListDto { Id = u.Id, Username = u.Username, FullName = u.FullName, Role = u.Role }).ToList();
            return new ServiceResponse<System.Collections.Generic.List<UserListDto>>(dtos);
        }

        public async Task<ServiceResponse<bool>> DeleteUserAsync(int id)
        {
            var user = await _repo.GetByIdAsync(id);
            if (user == null) return new ServiceResponse<bool>("Kullanıcı bulunamadı", false);
            // Kendi kendini silme kontrolü eklenebilir ama controller'dan kimin çağırdığını bilmiyoruz (ancak context'ten alabiliriz, şimdilik basit tutalım)
            await _repo.DeleteAsync(user);
            return new ServiceResponse<bool>(true);
        }
    }
}
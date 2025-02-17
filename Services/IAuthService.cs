using IdentityApi.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace IdentityAPI.Services
{
    public interface IAuthService
    {
        string GenerateJwtToken(string userId, string email);
        Task<IdentityResult> RegisterUserAsync(RegisterUserDto model);
    }
}
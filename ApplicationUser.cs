using Microsoft.AspNetCore.Identity;

namespace IdentityApi
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; }
    }
}

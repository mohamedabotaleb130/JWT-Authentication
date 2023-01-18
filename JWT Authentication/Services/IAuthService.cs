using JWT_Authentication.Models;

namespace JWT_Authentication.Services
{
	public interface IAuthService
	{
		Task<AuthenticationModel> RegisterAsync(RegisterModel model);
		Task<AuthenticationModel> GetTokenAsync(TokenRequestModel model);
		Task<string> AddRoleAsync(AddRoleModel model);
	}
}

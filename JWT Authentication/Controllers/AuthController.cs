using JWT_Authentication.Models;
using JWT_Authentication.Services;
using Microsoft.AspNetCore.Mvc;

namespace JWT_Authentication.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly IAuthService _authService;

		public AuthController(IAuthService authService)
		{
			_authService = authService;
		}
		[HttpPost("register")]
		public async Task<IActionResult> RegisterAsync([FromBody]RegisterModel model)
		{

			var result=await _authService.RegisterAsync(model);
			if(!ModelState.IsValid) {
			return BadRequest(result.Message);
			}
			return Ok(result);
		}

		[HttpPost("Token")]
		public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);

			}
			var result = await _authService.GetTokenAsync(model);
			if (!result.IsAuthenticated)
			{
				return BadRequest(result.Message);

			}
			return Ok(result);
		}

		[HttpPost("addrole")]
		public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);	
			}
			var result = await _authService.AddRoleAsync(model);
			if(string.IsNullOrEmpty(result))
			{
				return BadRequest(result);
			}
			return Ok(model);
		}

	}
}

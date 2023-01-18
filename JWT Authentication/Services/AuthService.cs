using JWT_Authentication.Models;
using JWT_Authentication.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_Authentication.Services
{
	public class AuthService : IAuthService
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly JWT _jwt;
		public AuthService(UserManager<ApplicationUser> userManager, IOptions <JWT> jwt, RoleManager<IdentityRole> roleManager)
		{
			_userManager = userManager;
			_jwt = jwt.Value;
			_roleManager = roleManager;
		}



		//RegisterAsync
		public async Task<AuthenticationModel> RegisterAsync(RegisterModel model)
		{
			if (await _userManager.FindByEmailAsync(model.Email) is not null)
				return new AuthenticationModel { Message = "Email  is already registered.!" };

			if (await _userManager.FindByEmailAsync(model.Username) is not null)
				return new AuthenticationModel { Message = "Username  is already registered.!" };

			var user = new ApplicationUser
			{
				UserName = model.Username,	
				Email = model.Email,
				FirstName = model.FirstName,
				LastName = model.LastName,


			};

			var result=await _userManager.CreateAsync(user,model.Password);
			if (!result.Succeeded)
			{
				var errors = string.Empty;
				foreach (var error in result.Errors)
				{
					errors += $"{error.Description},";
					
				}
				return new AuthenticationModel { Message=errors};
			}
			await _userManager.AddToRoleAsync(user, "User");

			var jwtSecurityToken=await CreateJwtToken(user);

			return new AuthenticationModel
			{
				Email = user.Email,
				ExpriesOn = jwtSecurityToken.ValidTo,
				IsAuthenticated = true,
				Roles = new List<string> { "User" },
				Token=new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
				UserName = user.UserName,
			
			};

		}
		//CreateJwtToken
		private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
		{
			var userClaims = await _userManager.GetClaimsAsync(user);
			var roles = await _userManager.GetRolesAsync(user);
			var roleClaims = new List<Claim>();
			foreach (var role in roles) 
				roleClaims.Add(new Claim("roles", role));
			//for (int i = 0; i < roles.Count; i++)
			//{
			//	roleClaims.Add(new Claim("roles", roles[i]));
			//}
			var claims = new[]
			{
				new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
				new Claim(JwtRegisteredClaimNames.Email, user.Email),
				//[can be used custom values]==> ex"uid"
				new Claim("uid", user.Id)
			}
			.Union(userClaims)
			.Union(roleClaims);
			var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
			var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
			var jwtSecurityToken = new JwtSecurityToken(
				issuer: _jwt.Issuer,
				audience: _jwt.Audience,
				claims: claims,
				expires: DateTime.Now.AddDays(_jwt.DurationInDays),
				signingCredentials: signingCredentials);
			return jwtSecurityToken;
		}
		//GetTokenAsync
		public async Task<AuthenticationModel> GetTokenAsync(TokenRequestModel model)
		{
			var authModel = new AuthenticationModel();
			var user = await _userManager.FindByEmailAsync(model.Email);
			if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
			{
				authModel.Message = "Email or password is incorrect!";
				return authModel;
			}
			var rolesList = await _userManager.GetRolesAsync(user);
			var jwtSecurityToken = await CreateJwtToken(user);

			authModel.IsAuthenticated = true;

			authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
			authModel.Email = user.Email;
			authModel.UserName = user.UserName;
			authModel.Roles = rolesList.ToList();
			return authModel;
		}

		public async Task<string> AddRoleAsync(AddRoleModel model)
		{
		
			var user=await _userManager.FindByIdAsync(model.UserId);
			if(user is null|| !await _roleManager.RoleExistsAsync(model.Role))
			{
				return "Invailed user ID OR Role";
			}
			if (await _userManager.IsInRoleAsync(user,model.Role))
			{
				return "User already assigned to this role ";

			}
			 var result=await _userManager.AddToRoleAsync(user,model.Role);
			return result.Succeeded ? string.Empty : "Sonething went wrong";
		}
	}
}

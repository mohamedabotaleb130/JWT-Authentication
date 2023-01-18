using Microsoft.VisualBasic;

namespace JWT_Authentication.Models
{
	public class AuthenticationModel
	{
		public string  Message { get; set; }
		public bool IsAuthenticated { get; set; }
		public string UserName { get; set; }
		
		public string Email { get; set; }
		public  List<string> Roles { get; set; }
		public  string Token { get; set; }
		public DateTime ExpriesOn { get; set; }
	}
}

using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace MvcCode.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        public HomeController(IConfiguration _config)
        {
            _configuration = _config;
        }
        [AllowAnonymous]
        public IActionResult Index() => View();

        public IActionResult Logout() => SignOut(CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);

        public IActionResult Login()
        {
            var authenticationProperties = new AuthenticationProperties();
            authenticationProperties.RedirectUri = _configuration.GetValue<string>(
               "ServerSettings:redirectUri");
            return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
        }

        public async Task<IActionResult> PersonalizarAsync()
        {
            if (User.Identity!.IsAuthenticated)
            {
                var authenticationProperties = new AuthenticationProperties();
                authenticationProperties.RedirectUri = _configuration.GetValue<string>(
               "ServerSettings:redirectUri");
                var httpClient = new HttpClient();
                var userInfo = new UserInfoRequest();
                var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;
                string authority = _configuration.GetValue<string>(
               "ServerSettings:authority");
                userInfo.Address = authority + "/connect/userinfo";
                userInfo.Token = userClaims?.FindFirst("access_token")?.Value;
                var userInfoProfile = await httpClient.GetUserInfoAsync(userInfo);

                foreach (var claim in userInfoProfile.Claims)
                {
                    if (claim.Type == "given_name")
                    {
                        authenticationProperties.Items.Add("login_hint", claim.Value);
                    }
                }
                authenticationProperties.Items.Add("acr_values", string.Format("action:manage"));
                return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
            }
            return Redirect("Index");
        }
        public IActionResult SingleSignOut()
        {
            var authenticationProperties = new AuthenticationProperties();
            authenticationProperties.RedirectUri = _configuration.GetValue<string>(
               "ServerSettings:redirectUri");
            return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
        }
    }
}
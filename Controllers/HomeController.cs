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
using Microsoft.AspNetCore.Http;

namespace MvcCode.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        public HomeController(IConfiguration _config)
        {
            _configuration = _config;
        }

        private async Task<int> GetClaims()
        {
            if (!User.Identity!.IsAuthenticated)
                return 1;
            var httpClient = new HttpClient();
            var userInfo = new UserInfoRequest();

            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;
            //You get the user's first and last name below:
            ViewBag.Name = userClaims?.FindFirst("audd")?.Value;

            // The 'preferred_username' claim can be used for showing the username
            ViewBag.Username = userClaims?.FindFirst("audd")?.Value;

            // The subject/ NameIdentifier claim can be used to uniquely identify the user across the web
            ViewBag.Subject = userClaims?.FindFirst("sub")?.Value;

            // TenantId is the unique Tenant Id - which represents an organization in Azure AD
            ViewBag.TenantId = userClaims?.FindFirst("isss")?.Value;
            string authority = _configuration.GetValue<string>(
               "ServerSettings:authority");
            userInfo.Address = authority + "/connect/userinfo";
            userInfo.Token = userClaims?.FindFirst("access_token")?.Value;

            ViewBag.userInfoProfile = await httpClient.GetUserInfoAsync(userInfo);
            return 1;
        }

        [AllowAnonymous]
        public async Task<IActionResult> Index() {
            var url = this.HttpContext.Session!.GetString("urlCallback");
            if (!string.IsNullOrWhiteSpace(url))
                return Redirect(url);
            url = this.HttpContext.Session!.GetString("origen");
            if(url != null)
            {
                ViewBag.Url = url;
                var i = await GetClaims();
            }
            
            return View();
        }

        public IActionResult Logout() => SignOut(CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
        [AllowAnonymous]
        public IActionResult Login1(string redirect, string urlCallback)
        {
            if (!string.IsNullOrWhiteSpace(redirect))
                this.HttpContext.Session.SetString("origen", redirect);
            if (!string.IsNullOrWhiteSpace(urlCallback))
                this.HttpContext.Session.SetString("urlCallback", urlCallback);
            return Redirect("Login");
        }
        public IActionResult Login(string redirect,string urlCallback)
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
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;


namespace MvcCode.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;

        private readonly IMemoryCache _cache;


        public HomeController(IConfiguration _config, IMemoryCache cache)
        {
            _configuration = _config;
            _cache = cache;
        }

        [AllowAnonymous]
        public async Task<IActionResult> Index()
        {
            
            var url = this.HttpContext.Request.Cookies.ContainsKey("urlCallback") ? this.HttpContext.Request.Cookies["urlCallback"] : "";
            if (User.Identity!.IsAuthenticated && !string.IsNullOrWhiteSpace(url))
            {
                return Redirect(url);
            }

            return View();
        }
        [AllowAnonymous]
        public IActionResult Logout()
        {
            if (!User.Identity!.IsAuthenticated)
            {
                var url = this.HttpContext.Request.Cookies.ContainsKey("urlCallback") ? this.HttpContext.Request.Cookies["urlCallback"] : "Index";
                return Redirect(url);
            }

            return SignOut(CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);

        }

        public IActionResult Login()
        {
            var authenticationProperties = new AuthenticationProperties();
            authenticationProperties.RedirectUri = Url.Action(nameof(Callback));
            return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
        }

        
        [AllowAnonymous]
        public IActionResult Login1(string redirect, string urlCallback)
        {
            if (!string.IsNullOrWhiteSpace(urlCallback))
                this.HttpContext.Response.Cookies.Append("urlCallback", urlCallback);
            if (!string.IsNullOrWhiteSpace(redirect))
                this.HttpContext.Session.SetString("redirect", redirect);
            return Redirect("Login");
        }
        [AllowAnonymous]
        public IActionResult Settings()
        {
            this.ViewBag.corsUrl = _configuration.GetValue<string>(
               "ServerSettings:corsUrl");
            this.ViewBag.clientId= _configuration.GetValue<string>(
               "ServerSettings:clientId");
            this.ViewBag.authority= _configuration.GetValue<string>(
               "ServerSettings:authority");
            return View();
        }
        [HttpGet]
        public async Task<IActionResult> Callback(string returnUrl = null, string remoteError = null)
        {

            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(OpenIdConnectDefaults.AuthenticationScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }
            var x = await HttpContext.GetTokenAsync("access_token");
            var id_token = await HttpContext.GetTokenAsync("id_token");

            var additionalLocalClaims = new List<Claim>();

            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);


            //            await HttpContext.SignInAsync(user.Id, name, provider, localSignInProps, additionalLocalClaims.ToArray());

            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);


            if (/*_interaction.IsValidReturnUrl(returnUrl) || */Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return Redirect("~/");

        }
        private async Task<(IdentityUser user, string provider, string providerUserId, IEnumerable<Claim> claims)>
      FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser?.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser?.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties?.Items["LoginProvider"];
            var providerUserId = userIdClaim.Value;

            //lógica de buscar usuario 
            //var user = await _userManager.FindByLoginAsync(provider, providerUserId);

            //return (user, provider, providerUserId, claims);
            return (null, provider, providerUserId, claims);
        }
        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal?.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var id_token = externalResult.Properties?.GetTokenValue("id_token");
            if (id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }
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

        [AllowAnonymous]
        public IActionResult Alive()
        {
            if (User.Identity!.IsAuthenticated)
                return View();
            return View("index");
        }
        [AllowAnonymous]

        public IActionResult KeepAlive()
        {
            return Json(new object());
        }
    }
}
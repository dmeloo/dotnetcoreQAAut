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
            authenticationProperties.RedirectUri = Url.Action(nameof(Callback));
            return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
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
    }
}
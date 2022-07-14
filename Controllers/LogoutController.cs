//using EntidadTestClient;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace MvcCode.Controllers
{
    public class LogoutController : Controller
    {
        private readonly SignInManager<IdentityUser> _signinManager;
        private readonly IConfiguration _config;
        public LogoutController(SignInManager<IdentityUser> signinManager, IConfiguration _config)
        {
            _signinManager = signinManager;
            this._config = _config;
        }

     
          public async Task <IActionResult> Home()
        {
            await _signinManager.SignOutAsync(/**/);

            var client = new HttpClient();
            var authConfiguration = _config.GetSection("AuthConfiguration");
            var clientId_aud = authConfiguration["Audience"];

            var disco = await client.GetDiscoveryDocumentAsync(authConfiguration["StsServerIdentityUrl"]);

            return Redirect(disco.EndSessionEndpoint);
        }

        public async Task<IActionResult> FrontChannelLogout(string sid, string iss)
        {
            if (User.Identity.IsAuthenticated)
            {
                var currentSid = User.FindFirst("sid")?.Value ?? "";
                if (string.Equals(currentSid, sid, StringComparison.Ordinal))
                {
                    await _signinManager.SignOutAsync(/*CookieAuthenticationDefaults.AuthenticationScheme*/);
                }
            }

            return NoContent();
        }
        // private async Task<ClaimsPrincipal> ValidateLogoutToken(string logoutToken)
        // {
        //     var claims = await ValidateJwt(logoutToken);

        //     if (claims.FindFirst("sub") == null && claims.FindFirst("sid") == null) throw new Exception("Invalid logout token");

        //     var nonce = claims.FindFirstValue("nonce");
        //     if (!String.IsNullOrWhiteSpace(nonce)) throw new Exception("Invalid logout token");

        //     var eventsJson = claims.FindFirst("events")?.Value;
        //     if (String.IsNullOrWhiteSpace(eventsJson)) throw new Exception("Invalid logout token");

        //     var events = JObject.Parse(eventsJson);
        //     var logoutEvent = events.TryGetValue("http://schemas.openid.net/event/backchannel-logout");
        //     if (logoutEvent == null) throw new Exception("Invalid logout token");

        //     return claims;
        // }

        private static async Task<ClaimsPrincipal> ValidateJwt(string jwt)
        {
            // read discovery document to find issuer and key material
            var client = new HttpClient();
            var disco = await client.GetDiscoveryDocumentAsync("authority");

            var keys = new List<SecurityKey>();
            foreach (var webKey in disco.KeySet.Keys)
            {
                var e = Base64Url.Decode(webKey.E);
                var n = Base64Url.Decode(webKey.N);

                var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n })
                {
                    KeyId = webKey.Kid
                };

                keys.Add(key);
            }

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = disco.Issuer,
                ValidAudience = "mvc.hybrid.backchannel",
                IssuerSigningKeys = keys,

                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role
            };

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            var user = handler.ValidateToken(jwt, parameters, out var _);
            return user;
        }
    }
}
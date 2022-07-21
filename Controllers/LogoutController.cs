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
    public class LogoutController : Controller
    {
        //private readonly SignInManager<IdentityUser> _signinManager;
        private readonly IConfiguration _config;
        public LogoutController(IConfiguration _config)
        {
            this._config = _config;
        }
        /// <summary>
        /// Realiza el deslogue de esta aplicación.
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="iss"></param>
        /// <returns></returns>
        public async Task<IActionResult> FrontChannelLogout(string sid, string iss)
        {
            if (User.Identity.IsAuthenticated)
            {
                var currentSid = User.FindFirst("sid")?.Value ?? "";
                if (string.Equals(currentSid, sid, StringComparison.Ordinal))
                {
                    await this.HttpContext.SignOutAsync();
                }
            }

            return NoContent();
        }

    }

}
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.Cors;
using Web.Models;

namespace MvcCode.Controllers
{
    /// <summary>
    /// controler que permite visualizar los claims de un usuario autenticado.
    /// </summary>
    public class ClaimsController : Controller
    {
        private readonly IConfiguration _configuration;
        public ClaimsController(IConfiguration _config)
        {
            _configuration = _config;
        }
        /// <summary>
        /// Visualiza los claims en la página del usuario logueado.
        /// </summary>
        /// <returns></returns>
        public IActionResult Index()
        {
            var httpClient = new HttpClient();
            var userInfo = new UserInfoRequest();
            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;

            ViewBag.userClaims = userClaims.Claims;
           
            return View();
        }
        /// <summary>
        /// Servicio que permite obtener los claims en json.
        /// </summary>
        /// <returns></returns>
        [EnableCors("PermitirApiRequest")]
        [AllowAnonymous]
        public IActionResult GetClaims() {
            
            if (!User.Identity!.IsAuthenticated)
                return Json(new object());
            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;

            AutenticacionDigital result = new AutenticacionDigital();
            foreach (var claim in userClaims.Claims)
            {
                Type t = result.GetType();
                var p = t.GetProperty(claim.Type);
                if (p != null)
                {
                    p.SetValue(result, claim.Value);
                }
            }

            return Json(result);
        }
    }
}
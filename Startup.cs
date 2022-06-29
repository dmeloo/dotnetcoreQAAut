using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Polly;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.HttpOverrides;

namespace MvcCode
{
    public class Startup
    {
        public IConfiguration Configuration { get; private set; }

        public Startup(IConfiguration configuration)
        {
            this.Configuration = configuration;
        }
        public void ConfigureServices(IServiceCollection services)
        {
            string redirectUri = Configuration.GetValue<string>(
               "ServerSettings:redirectUri");

            string clientId = Configuration.GetValue<string>(
               "ServerSettings:clientId");

            string clientSecret = Configuration.GetValue<string>(
               "ServerSettings:clientSecret");

            string authority = Configuration.GetValue<string>(
               "ServerSettings:authority");

            string redirectUriLogout = Configuration.GetValue<string>(
               "ServerSettings:redirectUriLogout");

            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

            services.AddControllersWithViews();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.Cookie.Name = CookieAuthenticationDefaults.CookiePrefix + CookieAuthenticationDefaults.AuthenticationScheme;
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                })
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.ResponseType = OpenIdConnectResponseType.Code;
                    options.RequireHttpsMetadata = true;
                    options.Authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, authority, "common");
                    options.ClientId = clientId;
                    options.ClientSecret = clientSecret;
                    options.UsePkce = true;
                    options.Scope.Clear();
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("email");
                    options.UseTokenLifetime = false;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.SaveTokens = true;
                    options.SecurityTokenValidator = new JwtSecurityTokenHandler
                    {
                        InboundClaimTypeMap = new Dictionary<string, string>()
                    };

                    options.TokenValidationParameters.NameClaimType = "name";
                    options.TokenValidationParameters.RoleClaimType = "role";
                    options.TokenValidationParameters.ValidateIssuer = false;
                    options.Events = new OpenIdConnectEvents
                    {
                        OnRedirectToIdentityProvider = context =>
                        {
                            if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                            {
                                if (context.Request.Path.Value == "/Home/Login" || context.Request.Path.Value == "/Home/Personalizar")
                                {
                                    if (context.Properties.Items.ContainsKey("acr_values"))
                                    {
                                        context.ProtocolMessage.AcrValues = context.Properties.Items["acr_values"];
                                    }
                                    if (context.Properties.Items.ContainsKey("login_hint"))
                                    {
                                        context.ProtocolMessage.LoginHint = context.Properties.Items["login_hint"];
                                    }
                                }
                                else
                                {
                                    context.ProtocolMessage.Prompt = "none";
                                }
                            }
                            return Task.CompletedTask;
                        },
                        OnRemoteFailure = context =>
                        {
                            if (context.Failure!.Message.Contains("login_required"))
                            {
                                context.Response.Redirect("/Home/Logout");
                                context.HandleResponse();
                            }
                            else
                            {
                                context.HandleResponse();
                                context.Response.Redirect("/?errormessage=" + context.Failure.Message);
                            }
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = context =>
                        {
                            /*var userClaims = context.Principal!.Identity as System.Security.Claims.ClaimsIdentity;
                            if (userClaims != null)
                            {
                                userClaims.AddClaim(new Claim("id_token", context.ProtocolMessage.IdToken));
                                userClaims.AddClaim(new Claim("access_token", context.ProtocolMessage.AccessToken));
                                userClaims.AddClaim(new Claim("audd", userClaims!.FindFirst("aud")!.Value));
                                userClaims.AddClaim(new Claim("isss", userClaims!.FindFirst("iss")!.Value));
                            }
                            */
                            return Task.CompletedTask;
                        },
                    };

                });

        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseForwardedHeaders(new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto });

            app.UseDeveloperExceptionPage();
            //app.UseHttpsRedirection();
             app.UseStaticFiles();            
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();
            
            //app.UseCookieAuthentication(new CookieAuthenticationOptions()
            //{
            //    AuthenticationScheme = "Cookies",
            //    AutomaticAuthenticate = true
            //});


            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute()
                    .RequireAuthorization();
            });
        }
    }
}
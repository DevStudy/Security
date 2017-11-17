using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace CookiePolicySample
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckPersistencePolicyNeeded = context => context.Request.PathBase.Equals("/NeedsPermision");
                // Allow persisting any auth cookies regardless of permission.
                options.OnAppendCookie = context => context.CanPersist |= context.CookieOptions.Purpose == CookiePurpose.Authentication;
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseCookiePolicy();
            app.UseAuthentication();

            app.Map("/NeedsPermision", NestedApp);
            app.Map("/NeedsNoPermission", NestedApp);
            NestedApp(app);
        }

        private void NestedApp(IApplicationBuilder app)
        {
            app.Run(async context =>
            {
                var path = context.Request.Path;
                switch (path)
                {
                    case "/Login":
                        var user = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "bob") },
                            CookieAuthenticationDefaults.AuthenticationScheme));
                        await context.SignInAsync(user);
                        break;
                    case "/Logout":
                        await context.SignOutAsync();
                        break;
                    case "/CreateTempCookie":
                        context.Response.Cookies.Append("Temp", "1");
                        break;
                    case "/RemoveTempCookie":
                        context.Response.Cookies.Delete("Temp");
                        break;
                    case "/GrantPermission":
                        context.Features.Get<IPersistencePermissionFeature>().GrantPermission();
                        break;
                    case "/WithdrawPermission":
                        context.Features.Get<IPersistencePermissionFeature>().WithdrawPermission();
                        break;
                }

                // TODO: Debug log when cookie is suppressed                    

                await HomePage(context);
            });
        }

        private async Task HomePage(HttpContext context)
        {
            var response = context.Response;
            var cookies = context.Request.Cookies;
            response.ContentType = "text/html";
            await response.WriteAsync("<html><body>\r\n");

            await response.WriteAsync($"<a href=\"{context.Request.PathBase}/\">Home</a><br>\r\n");
            await response.WriteAsync($"<a href=\"{context.Request.PathBase}/Login\">Login</a><br>\r\n");
            await response.WriteAsync($"<a href=\"{context.Request.PathBase}/Logout\">Logout</a><br>\r\n");
            await response.WriteAsync($"<a href=\"{context.Request.PathBase}/CreateTempCookie\">Create Temp Cookie</a><br>\r\n");
            await response.WriteAsync($"<a href=\"{context.Request.PathBase}/RemoveTempCookie\">Remove Temp Cookie</a><br>\r\n");
            await response.WriteAsync($"<a href=\"{context.Request.PathBase}/GrantPermission\">Grant Permission</a><br>\r\n");
            await response.WriteAsync($"<a href=\"{context.Request.PathBase}/WithdrawPermission\">Withdraw Permission</a><br>\r\n");
            await response.WriteAsync("<br>\r\n");
            await response.WriteAsync($"<a href=\"/NeedsPermision{context.Request.Path}\">Needs Permission</a><br>\r\n");
            await response.WriteAsync($"<a href=\"/NeedsNoPermission{context.Request.Path}\">Needs No Permission</a><br>\r\n");
            await response.WriteAsync("<br>\r\n");

            var feature = context.Features.Get<IPersistencePermissionFeature>();
            await response.WriteAsync($"Permissions: <br>\r\n");
            await response.WriteAsync($" - IsNeeded: {feature.IsPermissionNeeded} <br>\r\n");
            await response.WriteAsync($" - HasPerm: {feature.HasPermission} <br>\r\n");
            await response.WriteAsync($" - Can Persist: {feature.CanPersist} <br>\r\n");
            await response.WriteAsync("<br>\r\n");

            await response.WriteAsync($"{cookies.Count} Request Cookies:<br>\r\n");
            foreach (var cookie in cookies)
            {
                await response.WriteAsync($" - {cookie.Key} = {cookie.Value} <br>\r\n");
            }
            await response.WriteAsync("<br>\r\n");

            var responseCookies = response.Headers[HeaderNames.SetCookie];
            await response.WriteAsync($"{responseCookies.Count} Response Cookies:<br>\r\n");
            foreach (var cookie in responseCookies)
            {
                await response.WriteAsync($" - {cookie} <br>\r\n");
            }          

            await response.WriteAsync("</body></html>");
        }
    }
}

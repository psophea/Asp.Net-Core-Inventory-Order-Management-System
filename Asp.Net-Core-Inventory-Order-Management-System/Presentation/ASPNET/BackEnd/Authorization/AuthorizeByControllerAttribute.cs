namespace ASPNET.BackEnd.Authorization;

using System;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class AuthorizeByControllerAttribute : Attribute, IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        // respect AllowAnonymous
        if (context.ActionDescriptor.EndpointMetadata.Any(m => m is IAllowAnonymous))
        {
            return;
        }

        var user = context.HttpContext.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        // get controller name from route data
        var controllerName = context.RouteData.Values["controller"] as string;
        if (string.IsNullOrEmpty(controllerName))
        {
            // if can't determine controller, deny by default
            context.Result = new ForbidResult();
            return;
        }

        var roleName = Pluralize(controllerName);

        // use IAuthorizationService with a Roles requirement (respects role claim configuration)
        var authz = context.HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
        var requirement = new RolesAuthorizationRequirement(new[] { roleName });
        var authorized = await authz.AuthorizeAsync(user, resource: null, requirements: new[] { requirement });

        if (!authorized.Succeeded)
        {
            context.Result = new ForbidResult();
        }
    }

    // lightweight pluralization: handles typical English rules (y -> ies, s/x/ch/sh -> es, otherwise +s)
    private static string Pluralize(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return name;

        var lower = name.ToLowerInvariant();
        if (lower.Length > 1 && lower.EndsWith("y") && !"aeiou".Contains(lower[^2]))
        {
            return name.Substring(0, name.Length - 1) + "ies";
        }

        if (lower.EndsWith("s") || lower.EndsWith("x") || lower.EndsWith("z") || lower.EndsWith("ch") || lower.EndsWith("sh"))
        {
            return name + "es";
        }

        return name + "s";
    }
}
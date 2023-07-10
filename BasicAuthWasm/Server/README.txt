This code includes a dependency on Duende IdentityServer.
This is an open source product with a reciprocal license agreement. If you plan to use Duende IdentityServer in production this may require a license fee.
To see how to use Azure Active Directory for your identity please see https://aka.ms/aspnetidentityserver
To see if you require a commercial license for Duende IdentityServer please see https://aka.ms/identityserverlicense

Notes for Basic Authentication/Authorization in Blazor

Resources:

    ASP.NET Core Blazor authentication and authorization
    https://learn.microsoft.com/en-us/aspnet/core/blazor/security/webassembly/?view=aspnetcore-7.0

    IdentityManager
    https://github.com/carlfranklin/IdentityManagerLibrary

Client:

    Add CustomUserFactory.cs

    Add to Program.cs
        builder.Services.AddApiAuthorization()
            .AddAccountClaimsPrincipalFactory<CustomUserFactory>();

Server:

    appsettings.json:
        Change "DefaultConnection" to your app's Identity DB connection string

    Package Manager Console:
        run "update-database"

    Program.cs:
        Add at line 16:
            .AddRoles<IdentityRole>()

        Replace this:
            builder.Services.AddIdentityServer()
                .AddApiAuthorization<ApplicationUser, ApplicationDbContext>();
        With this:
            builder.Services.AddIdentityServer()
            .AddApiAuthorization<ApplicationUser, ApplicationDbContext>(options => {
                options.IdentityResources["openid"].UserClaims.Add("name");
                options.ApiResources.Single().UserClaims.Add("name");
                options.IdentityResources["openid"].UserClaims.Add("role");
                options.ApiResources.Single().UserClaims.Add("role");
            });

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Remove("role");

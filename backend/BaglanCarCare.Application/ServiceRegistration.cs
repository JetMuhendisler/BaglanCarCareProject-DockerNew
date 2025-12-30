using BaglanCarCare.Application.Interfaces.Services;
using BaglanCarCare.Application.Services;
using Microsoft.Extensions.DependencyInjection;
using AutoMapper;
using BaglanCarCare.Application.Mappings;
namespace BaglanCarCare.Application
{
    public static class ServiceRegistration
    {
        public static void AddApplicationServices(this IServiceCollection s)
        {
            s.AddAutoMapper(configuration => { configuration.AddProfile<GeneralMapping>(); });
            s.AddScoped<IAuthService, AuthManager>();
            s.AddScoped<IOrderService, OrderManager>(); 
            s.AddScoped<IPersonnelService, PersonnelManager>(); 
            s.AddScoped<IExpenseService, ExpenseManager>();
            s.AddScoped<ICatalogService, CatalogManager>();
            s.AddScoped<IDeletionRequestService, DeletionRequestManager>();
        }
    }
}

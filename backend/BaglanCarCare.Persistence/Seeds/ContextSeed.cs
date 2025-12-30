using BaglanCarCare.Domain.Entities;
using BaglanCarCare.Persistence.Contexts;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;
namespace BaglanCarCare.Persistence.Seeds
{
    public static class ContextSeed
    {
        public static async Task SeedAsync(BaglanCarCareDbContext context)
        {
            // Seed logic removed as Materials and ServiceDefinitions are deleted.
            await context.SaveChangesAsync();
        }
    }
}
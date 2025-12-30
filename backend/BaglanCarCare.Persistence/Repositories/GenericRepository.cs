using BaglanCarCare.Application.Interfaces.Repositories;
using BaglanCarCare.Domain.Common;
using BaglanCarCare.Domain.Entities;
using BaglanCarCare.Domain.Entities.Catalog; // Product entity'si için gerekli
using BaglanCarCare.Persistence.Contexts;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace BaglanCarCare.Persistence.Repositories
{
    public class GenericRepository<T> : IGenericRepository<T> where T : BaseEntity
    {
        private readonly BaglanCarCareDbContext _ctx;
        private readonly DbSet<T> _dbSet;

        public GenericRepository(BaglanCarCareDbContext c)
        {
            _ctx = c;
            _dbSet = _ctx.Set<T>();
        }

        public async Task<T> AddAsync(T e)
        {
            await _dbSet.AddAsync(e);
            await _ctx.SaveChangesAsync();
            return e;
        }

        public async Task UpdateAsync(T e)
        {
            _dbSet.Update(e);
            await _ctx.SaveChangesAsync();
        }

        public async Task DeleteAsync(T e)
        {
            _dbSet.Remove(e);
            await _ctx.SaveChangesAsync();
        }

        public async Task<List<T>> GetAllAsync()
        {
            // --- 1. ServiceTransaction İÇİN ÖZEL SORGUSU (MEVCUT) ---
            if (typeof(T) == typeof(ServiceTransaction))
            {
                return await _ctx.Set<ServiceTransaction>()
                    .Include(x => x.Vehicle)
                    .Include(x => x.Vehicle.Customer)
                    .Include(x => x.Personnels)
                    .Include(x => x.TransactionItems)
                    .ToListAsync() as List<T>;
            }

            // --- 2. PRODUCT (ÜRÜN) İÇİN ÖZEL SORGUSU (YENİ EKLENEN) ---
            // Bu blok sayesinde ürünleri çekerken Varyantları ve Fiyatları da dolu gelecek.
            if (typeof(T) == typeof(Product))
            {
                return await _ctx.Set<Product>()
                    .Include(x => x.Category)                 // Kategoriyi getir
                    .Include(x => x.Variants)                 // Varyantları (Mikron) getir
                    .ThenInclude(v => v.PartPrices)           // Varyantın içindeki Fiyatları getir (Derinlik 2)
                    .ToListAsync() as List<T>;
            }

            // Diğer tablolar için standart getirme
            return await _dbSet.ToListAsync();
        }

        public async Task<T> GetByIdAsync(int id)
        {
            // Tekil ürün çekerken de dolu gelmesi lazım
            if (typeof(T) == typeof(Product))
            {
                var entity = await _ctx.Set<Product>()
                    .Include(x => x.Category)
                    .Include(x => x.Variants)
                    .ThenInclude(v => v.PartPrices)
                    .FirstOrDefaultAsync(x => x.Id == id);
                return entity as T;
            }

            return await _dbSet.FindAsync(id);
        }

        public async Task<List<T>> GetAsync(Expression<Func<T, bool>> p)
        {
            return await _dbSet.Where(x => !x.IsDeleted).Where(p).ToListAsync();
        }

        // Include parametreli overload
        public async Task<List<T>> GetAllAsync(params Expression<Func<T, object>>[] includes)
        {
            IQueryable<T> query = _dbSet;
            if (includes != null)
            {
                foreach (var include in includes)
                {
                    query = query.Include(include);
                }
            }
            return await query.ToListAsync();
        }
    }
}
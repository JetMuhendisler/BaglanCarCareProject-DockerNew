using AutoMapper;
using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Interfaces.Repositories;
using BaglanCarCare.Application.Interfaces.Services;
using BaglanCarCare.Application.Wrappers;
using BaglanCarCare.Domain.Entities.Catalog;

namespace BaglanCarCare.Application.Services
{
    public class CatalogManager : ICatalogService
    {
        private readonly IGenericRepository<Product> _productRepo;
        private readonly IGenericRepository<Category> _categoryRepo;
        private readonly IGenericRepository<ProductVariant> _variantRepo;
        private readonly IGenericRepository<ProductPartPrice> _partRepo;
        private readonly IMapper _mapper;

        public CatalogManager(
            IGenericRepository<Product> productRepo,
            IGenericRepository<Category> categoryRepo,
            IGenericRepository<ProductVariant> variantRepo,
            IGenericRepository<ProductPartPrice> partRepo,
            IMapper mapper)
        {
            _productRepo = productRepo;
            _categoryRepo = categoryRepo;
            _variantRepo = variantRepo;
            _partRepo = partRepo;
            _mapper = mapper;
        }

        // ==========================================
        // 1. LEVEL: KATEGORİ İŞLEMLERİ
        // ==========================================
        public async Task<ServiceResponse<List<CategoryDto>>> GetAllCategoriesAsync()
        {
            var data = await _categoryRepo.GetAllAsync();
            return new ServiceResponse<List<CategoryDto>>(_mapper.Map<List<CategoryDto>>(data));
        }
        public async Task<ServiceResponse<int>> CreateCategoryAsync(CreateCategoryDto req)
        {
            var cat = _mapper.Map<Category>(req);
            await _categoryRepo.AddAsync(cat);
            return new ServiceResponse<int>(cat.Id);
        }
        public async Task<ServiceResponse<bool>> UpdateCategoryAsync(UpdateCategoryDto req)
        {
            var cat = await _categoryRepo.GetByIdAsync(req.Id);
            if (cat == null) return new ServiceResponse<bool>("Kategori yok", false);
            _mapper.Map(req, cat);
            await _categoryRepo.UpdateAsync(cat);
            return new ServiceResponse<bool>(true);
        }
        public async Task<ServiceResponse<bool>> DeleteCategoryAsync(int id)
        {
            var cat = await _categoryRepo.GetByIdAsync(id);
            if (cat == null) return new ServiceResponse<bool>("Kategori yok", false);
            await _categoryRepo.DeleteAsync(cat);
            return new ServiceResponse<bool>(true);
        }

        // ==========================================
        // 2. LEVEL: ÜRÜN (BASE) İŞLEMLERİ
        // ==========================================
        public async Task<ServiceResponse<List<ProductListDto>>> GetAllProductsAsync()
        {
            // GenericRepository'nin Include destekli GetAllAsync'ini kullandığından emin ol
            var data = await _productRepo.GetAllAsync();
            var dtos = _mapper.Map<List<ProductListDto>>(data);
            return new ServiceResponse<List<ProductListDto>>(dtos);
        }

        public async Task<ServiceResponse<ProductListDto>> GetProductByIdAsync(int id)
        {
            var p = await _productRepo.GetByIdAsync(id);
            if (p == null) return new ServiceResponse<ProductListDto>("Ürün yok");
            return new ServiceResponse<ProductListDto>(_mapper.Map<ProductListDto>(p));
        }

        public async Task<ServiceResponse<int>> CreateProductAsync(CreateProductDto req)
        {
            var product = _mapper.Map<Product>(req);
            // Kural: Eğer Micron varsa, ana fiyat 0 olmalı (veya frontend yönetmeli)
            if (product.HasMicron) product.BasePrice = 0;

            await _productRepo.AddAsync(product);
            return new ServiceResponse<int>(product.Id);
        }

        public async Task<ServiceResponse<bool>> UpdateProductAsync(UpdateProductDto req)
        {
            var p = await _productRepo.GetByIdAsync(req.Id);
            if (p == null) return new ServiceResponse<bool>("Ürün bulunamadı", false);

            _mapper.Map(req, p);
            if (p.HasMicron) p.BasePrice = 0; // Kuralı güncellemede de uygula

            await _productRepo.UpdateAsync(p);
            return new ServiceResponse<bool>(true);
        }

        public async Task<ServiceResponse<bool>> DeleteProductAsync(int id)
        {
            var p = await _productRepo.GetByIdAsync(id);
            if (p == null) return new ServiceResponse<bool>("Ürün yok", false);
            await _productRepo.DeleteAsync(p);
            return new ServiceResponse<bool>(true);
        }

        // ==========================================
        // 3. LEVEL: VARYANT (MICRON) İŞLEMLERİ
        // ==========================================
        public async Task<ServiceResponse<int>> CreateVariantAsync(CreateVariantDto req)
        {
            // Bağlı olduğu ürün micron destekliyor mu kontrol edilebilir ama zorunlu değil
            var variant = _mapper.Map<ProductVariant>(req);

            // Kural: Alt parça varsa, varyant fiyatı 0 olmalı
            if (variant.HasSubParts) variant.VariantPrice = 0;

            await _variantRepo.AddAsync(variant);
            return new ServiceResponse<int>(variant.Id);
        }

        public async Task<ServiceResponse<bool>> UpdateVariantAsync(UpdateVariantDto req)
        {
            var v = await _variantRepo.GetByIdAsync(req.Id);
            if (v == null) return new ServiceResponse<bool>("Varyant bulunamadı", false);

            _mapper.Map(req, v);
            if (v.HasSubParts) v.VariantPrice = 0;

            await _variantRepo.UpdateAsync(v);
            return new ServiceResponse<bool>(true);
        }

        public async Task<ServiceResponse<bool>> DeleteVariantAsync(int id)
        {
            var v = await _variantRepo.GetByIdAsync(id);
            if (v == null) return new ServiceResponse<bool>("Varyant yok", false);
            await _variantRepo.DeleteAsync(v);
            return new ServiceResponse<bool>(true);
        }

        // ==========================================
        // 4. LEVEL: PARÇA (SUB-PART) İŞLEMLERİ
        // ==========================================
        public async Task<ServiceResponse<List<PartPriceDto>>> GetPartPricesAsync(int variantId)
        {
            var prices = await _partRepo.GetAsync(x => x.ProductVariantId == variantId);
            var dtos = _mapper.Map<List<PartPriceDto>>(prices);
            return new ServiceResponse<List<PartPriceDto>>(dtos);
        }

        public async Task<ServiceResponse<int>> CreatePartPriceAsync(CreatePartPriceDto req)
        {
            var part = _mapper.Map<ProductPartPrice>(req);
            // Parça her zaman en alt seviyedir, fiyatı kesinlikle vardır.
            await _partRepo.AddAsync(part);
            return new ServiceResponse<int>(part.Id);
        }

        public async Task<ServiceResponse<bool>> UpdatePartPriceAsync(UpdatePartPriceDto req)
        {
            var p = await _partRepo.GetByIdAsync(req.Id);
            if (p == null) return new ServiceResponse<bool>("Parça bulunamadı", false);
            _mapper.Map(req, p);
            await _partRepo.UpdateAsync(p);
            return new ServiceResponse<bool>(true);
        }

        public async Task<ServiceResponse<bool>> DeletePartPriceAsync(int id)
        {
            var p = await _partRepo.GetByIdAsync(id);
            if (p == null) return new ServiceResponse<bool>("Parça yok", false);
            await _partRepo.DeleteAsync(p);
            return new ServiceResponse<bool>(true);
        }
    }
}
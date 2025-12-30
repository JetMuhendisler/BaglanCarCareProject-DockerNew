using AutoMapper;
using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Domain.Entities;
using BaglanCarCare.Domain.Entities.Catalog;
using System.Linq;

namespace BaglanCarCare.Application.Mappings
{
    public class GeneralMapping : Profile
    {
        public GeneralMapping()
        {
            // --- EXPENSE (Gider) ---
            CreateMap<ExpenseRecord, ExpenseDto>()
                .ForMember(dest => dest.Type, opt => opt.MapFrom(src => src.IsIncome ? 1 : 0));
            CreateMap<CreateExpenseDto, ExpenseRecord>()
                .ForMember(dest => dest.IsIncome, opt => opt.MapFrom(src => src.Type == 1));
            CreateMap<UpdateExpenseDto, ExpenseRecord>()
                .ForMember(dest => dest.IsIncome, opt => opt.MapFrom(src => src.Type == 1));

            // --- PERSONEL ---
            CreateMap<Personnel, PersonnelDto>()
                .ForMember(dest => dest.FullName, opt => opt.MapFrom(src =>
                    ((src.FirstName ?? "") + " " + (src.LastName ?? "")).Trim()
                ))
                .ReverseMap();

            CreateMap<CreatePersonnelDto, Personnel>();
            CreateMap<UpdatePersonnelDto, Personnel>();

            // ==================================================================
            // YENİ KATALOG YAPISI (BURASI DÜZELTİLDİ)
            // ==================================================================

            // 1. Kategori
            CreateMap<Category, CategoryDto>().ReverseMap();
            CreateMap<CreateCategoryDto, Category>();
            CreateMap<UpdateCategoryDto, Category>();

            // 2. Ürün (Product)
            // 'CreateProductRequestDto' yerine 'CreateProductDto' kullanıyoruz
            CreateMap<CreateProductDto, Product>();

            // 'UpdateProductRequestDto' yerine 'UpdateProductDto' kullanıyoruz
            CreateMap<UpdateProductDto, Product>();

            // 'ProductDetailDto' yerine 'ProductListDto' kullanıyoruz (Listeleme için)
            CreateMap<Product, ProductListDto>()
                .ForMember(dest => dest.CategoryName, opt => opt.MapFrom(src => src.Category.Name));

            // 3. Varyant (Variant)
            CreateMap<CreateVariantDto, ProductVariant>();
            CreateMap<UpdateVariantDto, ProductVariant>();

            // 'VariantDto' yerine 'VariantListDto' kullanıyoruz
            CreateMap<ProductVariant, VariantListDto>();

            // 4. Parça Fiyat (PartPrice)
            CreateMap<CreatePartPriceDto, ProductPartPrice>()
                 .ForMember(dest => dest.ProductVariantId, opt => opt.MapFrom(src => src.VariantId));

            CreateMap<UpdatePartPriceDto, ProductPartPrice>()
                 .ForMember(dest => dest.ProductVariantId, opt => opt.MapFrom(src => src.VariantId));

            // Listeleme için
            CreateMap<ProductPartPrice, PartPriceDto>();
        }
    }
}
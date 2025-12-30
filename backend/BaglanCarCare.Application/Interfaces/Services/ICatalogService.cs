using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Wrappers;

namespace BaglanCarCare.Application.Interfaces.Services
{
    public interface ICatalogService
    {
        // Kategori
        Task<ServiceResponse<List<CategoryDto>>> GetAllCategoriesAsync();
        Task<ServiceResponse<int>> CreateCategoryAsync(CreateCategoryDto request);
        Task<ServiceResponse<bool>> UpdateCategoryAsync(UpdateCategoryDto request);
        Task<ServiceResponse<bool>> DeleteCategoryAsync(int id);

        // Ürün (Base)
        Task<ServiceResponse<List<ProductListDto>>> GetAllProductsAsync();
        Task<ServiceResponse<ProductListDto>> GetProductByIdAsync(int id);
        Task<ServiceResponse<int>> CreateProductAsync(CreateProductDto request);
        Task<ServiceResponse<bool>> UpdateProductAsync(UpdateProductDto request);
        Task<ServiceResponse<bool>> DeleteProductAsync(int id);

        // Varyant (Micron)
        Task<ServiceResponse<int>> CreateVariantAsync(CreateVariantDto request);
        Task<ServiceResponse<bool>> UpdateVariantAsync(UpdateVariantDto request);
        Task<ServiceResponse<bool>> DeleteVariantAsync(int id);

        // Parça (Sub-Part)
        Task<ServiceResponse<List<PartPriceDto>>> GetPartPricesAsync(int variantId);
        Task<ServiceResponse<int>> CreatePartPriceAsync(CreatePartPriceDto request);
        Task<ServiceResponse<bool>> UpdatePartPriceAsync(UpdatePartPriceDto request);
        Task<ServiceResponse<bool>> DeletePartPriceAsync(int id);
    }
}
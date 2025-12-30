using BaglanCarCare.Application.DTOs;
using BaglanCarCare.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BaglanCarCare.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CatalogController : ControllerBase
    {
        private readonly ICatalogService _service;

        public CatalogController(ICatalogService service)
        {
            _service = service;
        }

        // --- KATEGORİ ---
        [HttpGet("categories")]
        public async Task<IActionResult> GetCategories() => Ok(await _service.GetAllCategoriesAsync());

        [Authorize(Roles = "Admin")]
        [HttpPost("categories")]
        public async Task<IActionResult> CreateCategory(CreateCategoryDto req) => Ok(await _service.CreateCategoryAsync(req));

        [Authorize(Roles = "Admin")]
        [HttpPut("categories")]
        public async Task<IActionResult> UpdateCategory(UpdateCategoryDto req) => Ok(await _service.UpdateCategoryAsync(req));

        [Authorize(Roles = "Admin")]
        [HttpDelete("categories/{id}")]
        public async Task<IActionResult> DeleteCategory(int id) => Ok(await _service.DeleteCategoryAsync(id));


        // --- ÜRÜN (LEVEL 1) ---
        [HttpGet("products")]
        public async Task<IActionResult> GetProducts() => Ok(await _service.GetAllProductsAsync());

        [HttpGet("products/{id}")]
        public async Task<IActionResult> GetProduct(int id) => Ok(await _service.GetProductByIdAsync(id));

        [Authorize(Roles = "Admin")]
        [HttpPost("products")]
        public async Task<IActionResult> CreateProduct(CreateProductDto req) => Ok(await _service.CreateProductAsync(req));

        [Authorize(Roles = "Admin")]
        [HttpPut("products")]
        public async Task<IActionResult> UpdateProduct(UpdateProductDto req) => Ok(await _service.UpdateProductAsync(req));

        [Authorize(Roles = "Admin")]
        [HttpDelete("products/{id}")]
        public async Task<IActionResult> DeleteProduct(int id) => Ok(await _service.DeleteProductAsync(id));


        // --- VARYANT (LEVEL 2) ---
        [Authorize(Roles = "Admin")]
        [HttpPost("variants")]
        public async Task<IActionResult> CreateVariant(CreateVariantDto req) => Ok(await _service.CreateVariantAsync(req));

        [Authorize(Roles = "Admin")]
        [HttpPut("variants")]
        public async Task<IActionResult> UpdateVariant(UpdateVariantDto req) => Ok(await _service.UpdateVariantAsync(req));

        [Authorize(Roles = "Admin")]
        [HttpDelete("variants/{id}")]
        public async Task<IActionResult> DeleteVariant(int id) => Ok(await _service.DeleteVariantAsync(id));


        // --- PARÇA (LEVEL 3) ---
        [Authorize(Roles = "Admin")]
        [HttpPost("parts")]
        public async Task<IActionResult> CreatePart(CreatePartPriceDto req) => Ok(await _service.CreatePartPriceAsync(req));

        [Authorize(Roles = "Admin")]
        [HttpPut("parts")]
        public async Task<IActionResult> UpdatePart(UpdatePartPriceDto req) => Ok(await _service.UpdatePartPriceAsync(req));

        [Authorize(Roles = "Admin")]
        [HttpDelete("parts/{id}")]
        public async Task<IActionResult> DeletePart(int id) => Ok(await _service.DeletePartPriceAsync(id));
    }
}
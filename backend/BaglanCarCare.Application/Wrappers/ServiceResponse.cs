namespace BaglanCarCare.Application.Wrappers
{
    public class ServiceResponse<T>
    {
        public T Data { get; set; }
        public bool Success { get; set; } = true;
        public string Message { get; set; }

        // 1. Boş Constructor
        public ServiceResponse() { }

        // 2. Başarılı Veri Dönüşü
        public ServiceResponse(T data)
        {
            Data = data;
            Success = true;
            Message = "İşlem başarılı";
        }

        // 3. Sadece Hata Mesajı (Yeni Yapı)
        public ServiceResponse(string message)
        {
            Success = false;
            Message = message;
            Data = default;
        }

        // 4. ESKİ KODLAR İÇİN GEREKLİ (Hata Düzeltici Constructor)
        // Manager sınıflarındaki new ServiceResponse<bool>("Yok", false) çağrılarını kurtarır.
        public ServiceResponse(string message, bool success)
        {
            Success = success;
            Message = message;
            Data = default;
        }

        // 5. Tam Kontrol (Opsiyonel)
        public ServiceResponse(T data, bool success, string message)
        {
            Data = data;
            Success = success;
            Message = message;
        }
        
        // 6. Veri ve Mesaj (Success = true kabul edilir)
        public ServiceResponse(T data, string message)
        {
            Data = data;
            Success = true;
            Message = message;
        }
    }
}